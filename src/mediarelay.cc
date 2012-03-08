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

#include "agent.hh"
#include "mediarelay.hh"

#include <poll.h>

#include <algorithm>
#include <list>

using namespace ::std;

void MediaSource::setDefaultSource(const char *ip, int port) {
	struct addrinfo *res = NULL;
	struct addrinfo hints = { 0 };
	char portstr[20];
	snprintf(portstr, sizeof(portstr), "%i", port);
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	int err = getaddrinfo(ip, portstr, &hints, &res);
	if (err != 0) {
		LOGE("MediaSource::setDefaultSource() failed for %s:%i : %s", ip, port, gai_strerror(err));
		return;
	}
	memcpy(&ss, res->ai_addr, res->ai_addrlen);
	slen = res->ai_addrlen;
	freeaddrinfo(res);
}

int MediaSource::recv(uint8_t *buf, size_t buflen) {
	slen = sizeof(ss);
	int err = recvfrom(fd, buf, buflen, 0, (struct sockaddr*) &ss, &slen);
	if (err == -1)
		slen = 0;
	return err;
}

int MediaSource::send(uint8_t *buf, size_t buflen) {
	int err;
	if (slen > 0) {
		err = sendto(fd, buf, buflen, 0, (struct sockaddr*) &ss, slen);
		return err;
	}
	return 0;
}

RelaySession::RelaySession(const std::string &bind_ip, const std::string & public_ip) :
		mBindIp(bind_ip), mPublicIp(public_ip) {
	mLastActivityTime = time(NULL);
	mFront = std::make_shared<RelaySessionRtp>();
	mFront->mRelay = this;
	mFront->mSession = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_local_addr(mFront->mSession, mBindIp.c_str(), -1);
	mFront->mSources[0].fd = rtp_session_get_rtp_socket(mFront->mSession);
	mFront->mSources[1].fd = rtp_session_get_rtcp_socket(mFront->mSession);
	mUsed = true;
}
RelaySession::RelaySession() {

}

RelaySession::~RelaySession() {

	rtp_session_destroy(mFront->mSession);

	for (std::list<std::shared_ptr<RelaySessionRtp>>::iterator it = mBacks.begin(); it != mBacks.end(); ++it) {
		rtp_session_destroy((*it)->mSession);
	}
}

std::shared_ptr<RelaySessionRtp> RelaySession::setFrontDefaultSource(const char *ip, int port) {
	mFront->mSources[0].setDefaultSource(ip, port);
	mFront->mSources[1].setDefaultSource(ip, port + 1);
	LOGD("%p FRONT=%s:%i -> %d", this, mFront->mSources[0].getAddress().c_str(), mFront->mSources[0].getPort(),rtp_session_get_local_port(mFront->mSession));
	return mFront;
}

void RelaySession::setBackDefaultSource(std::shared_ptr<RelaySessionRtp> rsr, const char *ip, int port) {
	rsr->mSources[0].setDefaultSource(ip, port);
	rsr->mSources[1].setDefaultSource(ip, port + 1);
}

std::shared_ptr<RelaySessionRtp> RelaySession::createBackDefaultSource(const char *ip, int port) {
	std::shared_ptr<RelaySessionRtp> rsr = std::make_shared<RelaySessionRtp>();
	rsr->mRelay = this;
	rsr->mSession = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_local_addr(rsr->mSession, mBindIp.c_str(), -1);
	rsr->mSources[0].fd = rtp_session_get_rtp_socket(rsr->mSession);
	rsr->mSources[1].fd = rtp_session_get_rtcp_socket(rsr->mSession);
	LOGD("%p BACK=%s:%i -> %d", this, rsr->mSources[0].getAddress().c_str(), rsr->mSources[0].getPort(), rtp_session_get_local_port(rsr->mSession));
	mBacks.push_back(rsr);
	return rsr;
}

void RelaySession::unuse() {
	mUsed = false;
}

void RelaySession::update(time_t curtime) {
	mLastActivityTime = curtime;
}

void RelaySession::transfer(time_t curtime, std::shared_ptr<RelaySessionRtp> src, int i) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	int len;
	mLastActivityTime = curtime;
	len = src->mSources[i].recv(buf, maxsize);
	if (len > 0) {
		if (src == mFront) {
			for (auto it = mBacks.begin(); it != mBacks.end(); ++it) {
				std::shared_ptr<RelaySessionRtp> dest = *it;
				dest->mSources[i].send(buf, len);
			}
		} else {
			mFront->mSources[i].send(buf, len);
		}
	}
}

MediaRelayServer::MediaRelayServer(const std::string &bind_ip, const std::string &public_ip) :
		mBindIp(bind_ip), mPublicIp(public_ip) {
	mRunning = false;
	if (pipe(mCtlPipe) == -1) {
		LOGF("Could not create MediaRelayServer control pipe.");
	}
}

void MediaRelayServer::start() {
	mRunning = true;
	pthread_create(&mThread, NULL, &MediaRelayServer::threadFunc, this);
}

MediaRelayServer::~MediaRelayServer() {
	if (mRunning) {
		mRunning = false;
		if (write(mCtlPipe[1], "e", 1) == -1)
			LOGE("MediaRelayServer: Fail to write to control pipe.");
		pthread_join(mThread, NULL);
	}
	for_each(mSessions.begin(), mSessions.end(), delete_functor<RelaySession>());
	close(mCtlPipe[0]);
	close(mCtlPipe[1]);
}

RelaySession *MediaRelayServer::addSession(RelaySession *s) {
	int count;
	mMutex.lock();
	mSessions.push_back(s);
	count = mSessions.size();
	mMutex.unlock();
	if (!mRunning)
		start();

	LOGD("There are now %i relay sessions running.", count);
	/*write to the control pipe to wakeup the server thread */
	if (write(mCtlPipe[1], "e", 1) == -1)
		LOGE("MediaRelayServer: fail to write to control pipe.");
	return s;
}

RelaySession *MediaRelayServer::createSession() {
	RelaySession *s = new RelaySession(mBindIp, mPublicIp);
	return addSession(s);
}

void MediaRelayServer::run() {
	int i;
	struct pollfd *pfds = NULL;
	int err;
	int pfds_size = 0, cur_pfds_size = 0;
	std::list<shared_ptr<RelaySessionRtp>> tmpRtps;
	while (mRunning) {
		mMutex.lock();
		tmpRtps.clear();
		for (auto it = mSessions.begin(); it != mSessions.end(); ++it) {
			RelaySession *rs = (*it);
			tmpRtps.push_back(rs->getFront());
			auto backs = rs->getBacks();
			for (auto it2 = backs.begin(); it2 != backs.end(); ++it2) {
				shared_ptr<RelaySessionRtp> ptr = *it2;
				tmpRtps.push_back(ptr);
			}
		}
		mMutex.unlock();
		pfds_size = tmpRtps.size() * 2 + 1;
		if (pfds_size > cur_pfds_size) {
			pfds = (struct pollfd*) realloc(pfds, pfds_size * sizeof(struct pollfd));
			cur_pfds_size = pfds_size;
		}

		// Fill fds
		i = 0;
		for (auto it = tmpRtps.begin(); it != tmpRtps.end(); ++it, i += 2) {
			pfds[i].fd = (*it)->mSources[0].fd;
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
			pfds[i + 1].fd = (*it)->mSources[1].fd;
			pfds[i + 1].events = POLLIN;
			pfds[i + 1].revents = 0;
		}
		pfds[pfds_size - 1].fd = mCtlPipe[0];
		pfds[pfds_size - 1].events = POLLIN;
		pfds[pfds_size - 1].revents = 0;

		err = poll(pfds, pfds_size, -1);

		if (err > 0) {
			if (pfds[pfds_size - 1].revents) {
				char tmp;
				if (read(mCtlPipe[0], &tmp, 1) == -1) {
					LOGE("Fail to read from control pipe.");
				}
			}
			time_t curtime = time(NULL);
			i = 0;
			for (auto it = tmpRtps.begin(); it != tmpRtps.end(); ++it, i += 2) {
				shared_ptr<RelaySessionRtp> ptr = (*it);
				if (pfds[i].revents & POLLIN) {
					ptr->mRelay->transfer(curtime, ptr, 0);
				}
				if (pfds[i + 1].revents & POLLIN) {
					ptr->mRelay->transfer(curtime, ptr, 1);
				}
			}
		}
		/*cleanup loop*/
		mMutex.lock();
		for (auto it = mSessions.begin(); it != mSessions.end();) {
			if (!(*it)->isUsed()) {
				delete *it;
				it = mSessions.erase(it);
			} else {
				++it;
			}
		}
		mMutex.unlock();
	}
	if (pfds)
		free(pfds);
}

void *MediaRelayServer::threadFunc(void *arg) {
	MediaRelayServer *zis = (MediaRelayServer*) arg;
	zis->run();
	return NULL;
}
