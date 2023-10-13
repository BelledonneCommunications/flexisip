/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010  Belledonne Communications SARL.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <flexisip/common.hh>
#include <flexisip/configmanager.hh>
#include "stun/flexisip_stun.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "stun.hh"

using namespace flexisip;
using namespace std;

StunServer::Init StunServer::sStaticInit; // The Init object is instanciated to load the config

StunServer::Init::Init() {
	ConfigItemDescriptor items[] = {{Boolean, "enabled", "Enable or disable stun server.", "true"},
	                                {String, "bind-address", "Local ip address where to bind the socket.", "0.0.0.0"},
	                                {Integer, "port", "STUN server port number.", "3478"},
	                                config_item_end};
	auto uS = make_unique<GenericStruct>("stun-server", "STUN server parameters.", 0);
	auto s = dynamic_cast<GenericStruct*>(GenericManager::get()->getRoot()->addChild(std::move(uS)));
	s->addChildrenValues(items);
}

StunServer::StunServer(int port) {
	mRunning = false;
	mPort = port;
	mSock = -1;
}

int StunServer::start() {
	int err;
	struct sockaddr_in laddr;
	std::string bind_address =
		GenericManager::get()->getRoot()->get<GenericStruct>("stun-server")->get<ConfigString>("bind-address")->read();

	if (bind_address.size() == 0)
		bind_address = "0.0.0.0";

	mSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (mSock == -1) {
		LOGE("Could not create socket: %s", strerror(errno));
		return -1;
	}

	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = inet_addr(bind_address.c_str());
	laddr.sin_port = htons(mPort);

	err = ::bind(mSock, (struct sockaddr *)&laddr, sizeof(laddr));
	if (err == -1) {
		LOGE("Could not bind STUN server to %s port %i", bind_address.c_str(), mPort);
		return -1;
	}

	mRunning = true;
	pthread_create(&mThread, NULL, &StunServer::threadfunc, this);
	return 0;
}

void StunServer::stop() {
	if (mRunning) {
		mRunning = false;
		pthread_join(mThread, NULL);
	}
}

void StunServer::run() {
	int err;

	/*set a high priority to this thread so that it answers fast*/
	err = setpriority(PRIO_PROCESS, 0, -20);
	if (err == -1) {
		LOGW("Fail to set high priority to stun server thread: %s", strerror(errno));
	}

	while (mRunning) {
		struct pollfd pfd[1];
		uint8_t buf[500];

		pfd[0].fd = mSock;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;

		err = poll(pfd, 1, 40);
		if (err > 0 && (pfd[0].revents & POLLIN)) {
			struct sockaddr_storage ss;
			socklen_t slen = sizeof(ss);
			err = recvfrom(mSock, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &slen);
			if (err > 0) {
				StunAddress4 from, myaddr, altaddr, dest;
				StunMessage resp;
				StunAtrString passwd;
				struct sockaddr_in *fromaddr = (struct sockaddr_in *)&ss;
				struct sockaddr_in srcaddr;
				socklen_t srcaddrlen = sizeof(srcaddr);

				bool_t changePort = FALSE;
				bool_t changeIP = FALSE;

				memset(&from, 0, sizeof(from));
				memset(&myaddr, 0, sizeof(myaddr));
				memset(&altaddr, 0, sizeof(altaddr));
				memset(&dest, 0, sizeof(dest));
				memset(&resp, 0, sizeof(resp));
				memset(&passwd, 0, sizeof(passwd));

				from.port = ntohs(fromaddr->sin_port);
				from.addr = ntohl(fromaddr->sin_addr.s_addr);

				if (getsockname(mSock, (struct sockaddr *)&srcaddr, &srcaddrlen) == -1) {
					LOGE("getsockname() error: %s", strerror(errno));
					continue;
				}
				myaddr.port = ntohs(srcaddr.sin_port);
				myaddr.addr = ntohl(srcaddr.sin_addr.s_addr);

				bool_t ret = stunServerProcessMsg((char *)buf, err, &from, &myaddr, &altaddr, &resp, &dest, &passwd,
												  &changeIP, &changePort);
				if (!ret) {
					LOGD("Fail to parse stun request.");
					continue;
				}
				if (changeIP == FALSE && changePort == FALSE) {
					unsigned int bytes = stunEncodeMessage(&resp, (char *)buf, sizeof(buf), &passwd);
					if (bytes > 0) {
						struct sockaddr_in destaddr;
						char tmp[32];
						destaddr.sin_family = AF_INET;
						destaddr.sin_port = htons(dest.port);
						destaddr.sin_addr.s_addr = htonl(dest.addr);
						err = sendto(mSock, buf, bytes, 0, (struct sockaddr *)&destaddr, sizeof(destaddr));
						if (err == -1) {
							LOGW("Fail to send stun response to %s:%i", inet_ntop(AF_INET, &destaddr, tmp, sizeof(tmp)),
								 dest.addr);
						}
					} else
						LOGE("stunEncodeMessage() failed.");
				} else
					LOGD("Received stun request with changeIP or changePort, not supported yet");
			}
		}
	}
}

void *StunServer::threadfunc(void *arg) {
	StunServer *zis = (StunServer *)arg;
	zis->run();
	return NULL;
}

StunServer::~StunServer() {
	if (mRunning)
		stop();
}
