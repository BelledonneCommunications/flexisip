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

MediaSource::MediaSource(RelaySession * relaySession, bool front, const string &default_ip) :
		mFront(front), mBehaviour(BehaviourType::All), mIp(default_ip), mPort(-1), mRelaySession(relaySession) {
	mSession = mRelaySession->getRelayServer()->createRtpSession();
	mSources[0] = rtp_session_get_rtp_socket(mSession);
	mSources[1] = rtp_session_get_rtcp_socket(mSession);
}

MediaSource::~MediaSource() {
	rtp_session_destroy(mSession);
}

void MediaSource::set(const string &ip, int port) {
	if (isFront())
		LOGD("MediaSource %p | Set | %s:%i <-> %i", this, ip.c_str(), port, getRelayPort());
	else
		LOGD("MediaSource %p | Set | %i <-> %s:%i", this, getRelayPort(), ip.c_str(), port);
	mPort = port;
	mIp = ip;
	struct addrinfo *res = NULL;
	struct addrinfo hints = { 0 };
	char portstr[20];
	int err;

	snprintf(portstr, sizeof(portstr), "%i", port);
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	err = getaddrinfo(ip.c_str(), portstr, &hints, &res);
	if (err != 0) {
		LOGE("MediaSource::MediaSource() failed for %s:%i : %s", ip.c_str(), port, gai_strerror(err));
	} else {
		memcpy(&mSockAddr[0], res->ai_addr, res->ai_addrlen);
		mSockAddrSize[0] = res->ai_addrlen;
		freeaddrinfo(res);
	}

	snprintf(portstr, sizeof(portstr), "%i", port + 1);
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	err = getaddrinfo(ip.c_str(), portstr, &hints, &res);
	if (err != 0) {
		LOGE("MediaSource::MediaSource() failed for %s:%i : %s", ip.c_str(), port, gai_strerror(err));
	} else {
		memcpy(&mSockAddr[1], res->ai_addr, res->ai_addrlen);
		mSockAddrSize[1] = res->ai_addrlen;
		freeaddrinfo(res);
	}
}

void MediaSource::setBehaviour(const BehaviourType &behaviour) {
	mBehaviour = behaviour;
	if (IS_LOGD) {
		const char *typeStr;
		switch (mBehaviour) {
		case None:
			typeStr = "None";
			break;

		case Send:
			typeStr = "Send";
			break;

		case Receive:
			typeStr = "Receive";
			break;

		case All:
			typeStr = "All";
			break;

		default:
			typeStr = "INVALID";
			break;
		}
		LOGD("MediaSource %p | %s", this, typeStr);
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
	mSockAddrSize[i] = sizeof(mSockAddr[i]);
	int err = recvfrom(mSources[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr[i], &mSockAddrSize[i]);
	if (err == -1) {
		mSockAddrSize[i] = 0;
	}
	return err;

}

int MediaSource::send(int i, uint8_t *buf, size_t buflen) {
	int err;
	if (mSockAddrSize[i] > 0) {
		err = sendto(mSources[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]);
		return err;
	}
	return 0;

}

RelaySession::RelaySession(MediaRelayServer *server) :
		mServer(server) {
	mLastActivityTime = time(NULL);
	mUsed = true;
}

shared_ptr<MediaSource> RelaySession::addFront(const string &default_ip) {
	shared_ptr<MediaSource> ms = make_shared<MediaSource>(this, true, default_ip);
	LOGD("MediaSource %p | Add | %s:%i <-> %i", ms.get(), ms->getIp().c_str(), ms->getPort(), ms->getRelayPort());
	mMutex.lock();
	mFronts.push_back(ms);
	mMutex.unlock();

	return ms;
}

void RelaySession::removeFront(const shared_ptr<MediaSource> &ms) {
	LOGD("MediaSource %p | Remove |  %s:%i <-> %i", ms.get(), ms->getIp().c_str(), ms->getPort(), ms->getRelayPort());
	mMutex.lock();
	mFronts.remove(ms);
	mMutex.unlock();
}

shared_ptr<MediaSource> RelaySession::addBack(const string &default_ip) {
	shared_ptr<MediaSource> ms = make_shared<MediaSource>(this, false, default_ip);
	LOGD("MediaSource %p | Add | %i <-> %s:%i", ms.get(), ms->getRelayPort(), ms->getIp().c_str(), ms->getPort());
	mMutex.lock();
	mBacks.push_back(ms);
	mMutex.unlock();

	return ms;
}

void RelaySession::removeBack(const shared_ptr<MediaSource> &ms) {
	LOGD("MediaSource %p | Remove | %i <-> %s:%i", ms.get(), ms->getRelayPort(), ms->getIp().c_str(), ms->getPort());
	mMutex.lock();
	mBacks.remove(ms);
	mMutex.unlock();
}

RelaySession::~RelaySession() {
}

void RelaySession::unuse() {
	mUsed = false;
}

void RelaySession::transfer(time_t curtime, const shared_ptr<MediaSource> &org, int i) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	int recv_len;
	int send_len;

	mLastActivityTime = curtime;
	recv_len = org->recv(i, buf, maxsize);
	if (recv_len > 0) {
		if (org->getBehaviour() & MediaSource::Send) {
			list<shared_ptr<MediaSource>> list;
			if (org->isFront()) {
				list = mBacks;
			} else {
				list = mFronts;
			}
			mMutex.lock();
			auto it = list.begin();
			if (it != list.end()) {
				while (it != list.end()) {
					const shared_ptr<MediaSource> &dest = (*it);
					if (dest->getBehaviour() & MediaSource::Receive) {
						//LOGD("%s:%i -> %i | size = %i | %i -> %s:%i", org->getIp().c_str(), org->getPort(), org->getRelayPort() + i, recv_len, dest->getRelayPort() +i, dest->getIp().c_str(), dest->getPort());
						send_len = dest->send(i, buf, recv_len);
						if (send_len != recv_len) {
							LOGW("Only %i bytes sent on %i bytes Port=%i For=%s:%i Error=%s", send_len, recv_len, dest->getRelayPort() + i, dest->getIp().c_str(), dest->getPort(), strerror(errno));
						}
					}
					++it;
				}
			}
			mMutex.unlock();
		}
	} else if (recv_len < 0) {
		LOGW("Error on read Port=%i For=%s:%i Error=%s", org->getRelayPort() + i, org->getIp().c_str(), org->getPort(), strerror(errno));
	}
}

MediaRelayServer::MediaRelayServer(Agent *agent) :
		mAgent(agent) {
	mRunning = false;

	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::MediaRelay");
	mMinPort = ma->get<ConfigInt>("sdp-port-range-min")->read();
	mMaxPort = ma->get<ConfigInt>("sdp-port-range-max")->read();

	if (pipe(mCtlPipe) == -1) {
		LOGF("Could not create MediaRelayServer control pipe.");
	}
}
Agent *MediaRelayServer::getAgent() {
	return mAgent;
}
RtpSession *MediaRelayServer::createRtpSession() {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
	for (int i = 0; i < 100; ++i) {
		int port = ((rand() % (mMaxPort - mMinPort)) + mMinPort) & 0xfffe;

		if (rtp_session_set_local_addr(session, mAgent->getBindIp().c_str(), port, port+1) == 0) {
			return session;
		}
	}

	LOGW("Could not find a random port for %s !", mAgent->getBindIp().c_str());
	return session;
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
	RelaySession *s = new RelaySession(this);
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
	list<shared_ptr<MediaSource>> mediaSources;

	while (mRunning) {
		mMutex.lock();
		mediaSources.clear();
		pfds_size = 1;
		for (auto it = mSessions.begin(); it != mSessions.end(); ++it) {
			RelaySession *ptr = *it;
			ptr->getMutex().lock();

			const list<shared_ptr<MediaSource>>& fronts = ptr->getFronts();
			for (auto it2 = fronts.begin(); it2 != fronts.end(); ++it2) {
				mediaSources.push_back(*it2);
			}

			const list<shared_ptr<MediaSource>>& backs = ptr->getBacks();
			for (auto it2 = backs.begin(); it2 != backs.end(); ++it2) {
				mediaSources.push_back(*it2);
			}

			pfds_size += (fronts.size() + backs.size()) * 2;
			ptr->getMutex().unlock();
		}
		mMutex.unlock();

		if (pfds_size > cur_pfds_size) {
			pfds = (struct pollfd*) realloc(pfds, pfds_size * sizeof(struct pollfd));
			cur_pfds_size = pfds_size;
		}

		int i = 0;
		for (auto it = mediaSources.begin(); it != mediaSources.end(); ++it) {
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
			int i = 0;
			for (auto it = mediaSources.begin(); it != mediaSources.end(); ++it) {
				if (pfds[i].revents & POLLIN) {
					RelaySession *s = (*it)->getRelaySession();
					if (s->isUsed()) {
						s->transfer(curtime, (*it), 0);
					}
				}
				if (pfds[i + 1].revents & POLLIN) {
					RelaySession *s = (*it)->getRelaySession();
					if (s->isUsed()) {
						s->transfer(curtime, (*it), 1);
					}
				}
				i += 2;
			}
		}

		/*cleanup loop*/
		mMutex.lock();
		for (auto it = mSessions.begin(); it != mSessions.end();) {
			if (!(*it)->isUsed()) {
				delete *it;
				it = mSessions.erase(it);
				LOGD("There are now %i relay sessions running.", (int) mSessions.size());
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
