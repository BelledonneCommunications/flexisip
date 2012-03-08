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

MediaSource::MediaSource(const std::string &ip, int port) :
		mIp(ip), mPort(port) {
	struct addrinfo *res = NULL;
	struct addrinfo hints = { 0 };
	char portstr[20];
	snprintf(portstr, sizeof(portstr), "%i", port);
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	int err = getaddrinfo(ip.c_str(), portstr, &hints, &res);
	if (err != 0) {
		LOGE("MediaSource::MediaSource() failed for %s:%i : %s", ip.c_str(), port, gai_strerror(err));
	} else {
		memcpy(&mSockAddr, res->ai_addr, res->ai_addrlen);
		mSockAddrSize = res->ai_addrlen;
		freeaddrinfo(res);
	}
}

MediaSource::MediaSource(const struct sockaddr_storage &sockaddr, socklen_t sockaddr_size) :
		mSockAddrSize(sockaddr_size) {
	memcpy(&mSockAddr, &sockaddr, sockaddr_size);
	char buff[256];
	const char *ret = inet_ntop(AF_INET, &((struct sockaddr_in *) &sockaddr)->sin_addr, buff, sizeof(buff));
	if (ret == NULL) {
		LOGE("MediaSource::MediaSource() failed for %p:", &sockaddr);
	} else {
		mIp = std::string(ret);
		mPort = ntohs(((struct sockaddr_in *)&sockaddr)->sin_port);
	}
}

RelaySession::RelaySession(const std::string &bind_ip, const std::string & public_ip) :
		mBindIp(bind_ip), mPublicIp(public_ip) {
	mLastActivityTime = time(NULL);
	mSession[0] = rtp_session_new(RTP_SESSION_SENDRECV);
	mSession[1] = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_local_addr(mSession[0], mBindIp.c_str(), -1);
	rtp_session_set_local_addr(mSession[1], mBindIp.c_str(), -1);
	mSources[0] = rtp_session_get_rtp_socket(mSession[0]);
	mSources[1] = rtp_session_get_rtp_socket(mSession[1]);
	mSources[2] = rtp_session_get_rtcp_socket(mSession[0]);
	mSources[3] = rtp_session_get_rtcp_socket(mSession[1]);
	mUsed = true;
}

int RelaySession::getFrontPort() const {
	return rtp_session_get_local_port(mSession[0]);
}

int RelaySession::getBackPort() const {
	return rtp_session_get_local_port(mSession[1]);
}

void RelaySession::addFront(const std::string &ip, int port) {
	MediaSource src(ip, port);
	LOGD("Add Front %s:%i", ip.c_str(), port);
	mMutex.lock();
	addFront(src);
	mMutex.unlock();
}

void RelaySession::addBack(const std::string &ip, int port) {
	MediaSource src(ip, port);
	LOGD("Add Back %s:%i", ip.c_str(), port);
	mMutex.lock();
	addBack(src);
	mMutex.unlock();
}

void RelaySession::addFront(const MediaSource&src) {
	auto it = std::find(mFront.begin(), mFront.end(), src);
	if (it == mFront.end()) {
		mFront.push_back(src);
	}
}

void RelaySession::removeFront(const std::string &ip, int port) {
	MediaSource src(ip, port);
	LOGD("Remove Front %s:%i", ip.c_str(), port);
	auto it = std::find(mFront.begin(), mFront.end(), src);
	if (it != mFront.end()) {
		mFront.erase(it);
	}
}

void RelaySession::addBack(const MediaSource&src) {
	auto it = std::find(mBack.begin(), mBack.end(), src);
	if (it == mBack.end()) {
		mBack.push_back(src);
	}
}

void RelaySession::removeBack(const std::string &ip, int port) {
	MediaSource src(ip, port);
	LOGD("Remove Back %s:%i", ip.c_str(), port);
	auto it = std::find(mBack.begin(), mBack.end(), src);
	if (it != mBack.end()) {
		mBack.erase(it);
	}
}

RelaySession::~RelaySession() {
	rtp_session_destroy(mSession[0]);
	rtp_session_destroy(mSession[1]);
}

void RelaySession::unuse() {
	mUsed = false;
}

void RelaySession::fillPollFd(struct pollfd *tab) {
	int i;
	for (i = 0; i < 4; ++i) {
		tab[i].fd = mSources[i];
		tab[i].events = POLLIN;
		tab[i].revents = 0;
	}
}

void RelaySession::transfer(time_t curtime, struct pollfd *tab) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	struct sockaddr_storage ss;
	socklen_t slen;
	int recv_len;
	int send_len;
	int i;

	mMutex.lock();
	for (i = 0; i < 4; i += 2) {
		if (tab[i].revents & POLLIN) {
			mLastActivityTime = curtime;
			recv_len = recvfrom(mSources[i], buf, maxsize, 0, (struct sockaddr*) &ss, &slen);
			if (recv_len > 0) {
				MediaSource src(ss, slen);
				addFront(src);
				std::list<MediaSource>::iterator it = mBack.begin();
				if (it != mBack.end()) {
					while (it != mBack.end()) {
						const MediaSource &dest = *it;
						//LOGD("(%i)%s:%i -> (%i)%s:%i", getFrontPort(), src.getIp().c_str(), src.getPort(), getBackPort(), dest.getIp().c_str(), dest.getPort());
						send_len = sendto(mSources[i + 1], buf, recv_len, 0, (const struct sockaddr*) &dest.getSockAddr(), dest.getSockAddrSize());
						if (send_len != recv_len) {
							//LOGW("Only %i bytes sent on %i bytes: %s", send_len, recv_len, strerror(errno));
							it = mBack.erase(it);
						} else {
							++it;
						}
					}
				} else {
					//LOGD("%s:%i -> GARBAGE", src.getIp().c_str(), src.getPort());
				}
			}
		}
		if (tab[i + 1].revents & POLLIN) {
			mLastActivityTime = curtime;
			recv_len = recvfrom(mSources[i + 1], buf, maxsize, 0, (struct sockaddr*) &ss, &slen);
			if (recv_len > 0) {
				MediaSource src(ss, slen);
				addBack(src);
				std::list<MediaSource>::iterator it = mFront.begin();
				if (it != mFront.end()) {
					while (it != mFront.end()) {
						const MediaSource &dest = *it;
						//LOGD("(%i)%s:%i -> (%i)%s:%i", getBackPort(), src.getIp().c_str(), src.getPort(), getFrontPort(), dest.getIp().c_str(), dest.getPort());
						send_len = sendto(mSources[i], buf, recv_len, 0, (const struct sockaddr*) &dest.getSockAddr(), dest.getSockAddrSize());
						if (send_len != recv_len) {
							//LOGW("Only %i bytes sent on %i bytes: %s", send_len, recv_len, strerror(errno));
							it = mFront.erase(it);
						} else {
							++it;
						}
					}
				} else {
					//LOGD("%s:%i -> GARBAGE", src.getIp().c_str(), src.getPort());
				}
			}
		}
	}
	mMutex.unlock();
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

RelaySession *MediaRelayServer::createSession() {
	RelaySession *s = new RelaySession(mBindIp, mPublicIp);
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

void MediaRelayServer::run() {
	int sessionCount;
	int i;
	struct pollfd *pfds = NULL;
	list<RelaySession*>::iterator it;
	int err;
	int pfds_size = 0, cur_pfds_size = 0;

	while (mRunning) {
		mMutex.lock();
		sessionCount = mSessions.size();
		mMutex.unlock();
		pfds_size = (sessionCount * 4) + 1;
		if (pfds_size > cur_pfds_size) {
			pfds = (struct pollfd*) realloc(pfds, pfds_size * sizeof(struct pollfd));
			cur_pfds_size = pfds_size;
		}
		for (i = 0, it = mSessions.begin(); i < sessionCount; ++i, ++it) {
			(*it)->fillPollFd(&pfds[i * 4]);
		}

		pfds[sessionCount * 4].fd = mCtlPipe[0];
		pfds[sessionCount * 4].events = POLLIN;
		pfds[sessionCount * 4].revents = 0;

		err = poll(pfds, (sessionCount * 4) + 1, -1);
		if (err > 0) {
			if (pfds[sessionCount * 4].revents) {
				char tmp;
				if (read(mCtlPipe[0], &tmp, 1) == -1) {
					LOGE("Fail to read from control pipe.");
				}
			}
			time_t curtime = time(NULL);
			for (i = 0, it = mSessions.begin(); i < sessionCount; ++i, ++it) {
				RelaySession *s = (*it);
				if (s->isUsed()) {
					s->transfer(curtime, &pfds[i * 4]);
				}
			}
		}
		/*cleanup loop*/
		mMutex.lock();
		for (it = mSessions.begin(); it != mSessions.end();) {
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
