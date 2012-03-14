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

MediaSource::MediaSource(RelaySession * relaySession) :
		mInit(false), mSession(NULL), mRelaySession(relaySession) {
	mSession = rtp_session_new(RTP_SESSION_SENDRECV);
	rtp_session_set_local_addr(mSession, relaySession->getBindIp().c_str(), -1);
	mSources[0] = rtp_session_get_rtp_socket(mSession);
	mSources[1] = rtp_session_get_rtcp_socket(mSession);
}

MediaSource::~MediaSource() {
	if (mSession != NULL) {
		rtp_session_destroy(mSession);
	}
}

void MediaSource::set(const string &ip, int port) {
	mPort = port;
	mIp = ip;
	mInit = true;

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

void MediaSource::set(const struct sockaddr_storage &sockaddr, socklen_t sockaddr_size) {
	mInit = true;
	mSockAddrSize = sockaddr_size;
	memcpy(&mSockAddr, &sockaddr, sockaddr_size);
	char buff[256];
	const char *ret = inet_ntop(AF_INET, &((struct sockaddr_in *) &sockaddr)->sin_addr, buff, sizeof(buff));
	if (ret == NULL) {
		LOGE("MediaSource::MediaSource() failed for %p:", &sockaddr);
	} else {
		mIp = string(ret);
		mPort = ntohs(((struct sockaddr_in *)&sockaddr)->sin_port);
	}
}

void MediaSource::fillPollFd(struct pollfd *tab) {
	for (int i = 0; i < 2; ++i) {
		tab[i].fd = mSources[i];
		tab[i].events = POLLIN;
		tab[i].revents = 0;
	}
}
int MediaSource::recv(int i, uint8_t *buf, size_t buflen) {
	return recvfrom(mSources[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr, &mSockAddrSize);
}

int MediaSource::send(int i, uint8_t *buf, size_t buflen) {
	return sendto(mSources[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr, mSockAddrSize);
}

RelaySession::RelaySession(const string &bind_ip, const string & public_ip) :
		mBindIp(bind_ip), mPublicIp(public_ip), mFront(make_shared<MediaSource>(this)) {
	mLastActivityTime = time(NULL);
	mUsed = true;
}

std::shared_ptr<MediaSource> RelaySession::addBack() {
	shared_ptr<MediaSource> ms = make_shared<MediaSource>(this);

	mMutex.lock();
	mBacks.push_back(ms);
	mMutex.unlock();

	return ms;
}

void RelaySession::removeBack(const std::shared_ptr<MediaSource> &ms) {
	mMutex.lock();
	mBacks.remove(ms);
	mMutex.unlock();
}

RelaySession::~RelaySession() {
}

void RelaySession::unuse() {
	mUsed = false;
}

void RelaySession::transfer(time_t curtime, const shared_ptr<MediaSource> &org) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	int recv_len;
	int send_len;

	mMutex.lock();
	mLastActivityTime = curtime;
	if (org == mFront) {
		for (int i = 0; i < 2; ++i) {
			recv_len = mFront->recv(i, buf, maxsize);
			if (recv_len > 0) {
				auto it = mBacks.begin();
				if (it != mBacks.end()) {
					while (it != mBacks.end()) {
						const shared_ptr<MediaSource> &dest = (*it);
						if (dest->isInit()) {
							//LOGD("%s:%i -> %s:%i", mFront->getIp().c_str(), mFront->getPort(), dest->getIp().c_str(), dest->getPort());
							send_len = dest->send(i, buf, recv_len);
							if (send_len != recv_len) {
								LOGW("Only %i bytes sent on %i bytes: %s", send_len, recv_len, strerror(errno));
							}
						}
						++it;
					}
				}
			}

		}
	} else if (mFront->isInit()) {
		for (int i = 0; i < 2; ++i) {
			recv_len = org->recv(i, buf, maxsize);
			if (recv_len > 0) {
				//LOGD("%s:%i -> %s:%i", org->getIp().c_str(), org->getPort(), mFront->getIp().c_str(), mFront->getPort());
				send_len = mFront->send(i, buf, recv_len);
				if (send_len != recv_len) {
					LOGW("Only %i bytes sent on %i bytes: %s", send_len, recv_len, strerror(errno));
				}
			}
		}
	}
	mMutex.unlock();
}

MediaRelayServer::MediaRelayServer(const string &bind_ip, const string &public_ip) :
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

void MediaRelayServer::update() {
	/*write to the control pipe to wakeup the server thread */
	if (write(mCtlPipe[1], "e", 1) == -1)
		LOGE("MediaRelayServer: fail to write to control pipe.");
}

void MediaRelayServer::run() {
	struct pollfd *pfds = NULL;
	int err;
	int pfds_size = 0, cur_pfds_size = 0;
	list<shared_ptr<MediaSource>> list;

	while (mRunning) {
		mMutex.lock();
		list.clear();
		pfds_size = 1;
		for (auto it = mSessions.begin(); it != mSessions.end(); ++it) {
			RelaySession *ptr = *it;
			ptr->mMutex.lock();
			if (ptr->getFront()->isInit()) {
				list.push_back(ptr->getFront());
				pfds_size += 2;
			}

			const std::list<std::shared_ptr<MediaSource>>& backs = ptr->getBacks();
			for (auto it2 = backs.begin(); it2 != backs.end(); ++it2) {
				if ((*it2)->isInit()) {
					list.push_back(*it2);
					pfds_size += 2;
				}
			}
			ptr->mMutex.unlock();
		}
		mMutex.unlock();

		if (pfds_size > cur_pfds_size) {
			pfds = (struct pollfd*) realloc(pfds, pfds_size * sizeof(struct pollfd));
			cur_pfds_size = pfds_size;
		}

		int i = 0;
		for (auto it = list.begin(); it != list.end(); ++it) {
			(*it)->fillPollFd(&pfds[i]);
			i += 2;
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
			for (auto it = list.begin(); it != list.end(); ++it) {
				RelaySession *s = (*it)->getRelaySession();
				if (s->isUsed()) {
					s->transfer(curtime, (*it));
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
