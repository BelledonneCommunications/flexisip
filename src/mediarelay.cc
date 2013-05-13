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

#include "flexisip-config.h"
#include "agent.hh"
#include "mediarelay.hh"

#include <poll.h>

#include <algorithm>
#include <list>


using namespace ::std;

RelayChannel::RelayChannel(RelaySession * relaySession, bool front, const std::pair<std::string,std::string> &relayIps) :
		mFront(front), mBehaviour(BehaviourType::All), mPublicIp(relayIps.first), mIp(std::string("undefined")), mPort(-1), mRelaySession(relaySession) {
	mSession = mRelaySession->getRelayServer()->createRtpSession(relayIps.second);
	mSources[0] = rtp_session_get_rtp_socket(mSession);
	mSources[1] = rtp_session_get_rtcp_socket(mSession);
}

bool RelayChannel::checkSocketsValid() {
	return mSources[0] != -1 && mSources[1] != -1;
}
RelayChannel::~RelayChannel() {
	rtp_session_destroy(mSession);
}

void RelayChannel::set(const string &ip, int port) {
	if (isFront())
		LOGD("RelayChannel %p | Set | %s:%i <-> %i", this, ip.c_str(), port, getRelayPort());
	else
		LOGD("RelayChannel %p | Set | %i <-> %s:%i", this, getRelayPort(), ip.c_str(), port);
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
		LOGE("RelayChannel::RelayChannel() failed for %s:%i : %s", ip.c_str(), port, gai_strerror(err));
	} else {
		memcpy(&mSockAddr[0], res->ai_addr, res->ai_addrlen);
		mSockAddrSize[0] = res->ai_addrlen;
		freeaddrinfo(res);
	}

	snprintf(portstr, sizeof(portstr), "%i", port + 1);
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	err = getaddrinfo(ip.c_str(), portstr, &hints, &res);
	if (err != 0) {
		LOGE("RelayChannel::RelayChannel() failed for %s:%i : %s", ip.c_str(), port, gai_strerror(err));
	} else {
		memcpy(&mSockAddr[1], res->ai_addr, res->ai_addrlen);
		mSockAddrSize[1] = res->ai_addrlen;
		freeaddrinfo(res);
	}
}

void RelayChannel::setBehaviour(const BehaviourType &behaviour) {
	mBehaviour=behaviour;
	switch (behaviour) {
		case None:
			SLOGD << "RelayChannel " << this << " | " << "None";
			break;
		case Send:
			SLOGD << "RelayChannel " << this << " | " << "Send";
			break;
		case Receive:
			SLOGD << "RelayChannel " << this << " | " << "Receive";
			break;
		case All:
			SLOGD << "RelayChannel " << this << " | " << "All";
			break;
		default:
			SLOGD << "RelayChannel " << this << " | " << "INVALID";
			break;
	};
}

void RelayChannel::fillPollFd(struct pollfd *tab) {
	for (int i = 0; i < 2; ++i) {
		tab[i].fd = mSources[i];
		tab[i].events = POLLIN;
		tab[i].revents = 0;
	}
}

int RelayChannel::recv(int i, uint8_t *buf, size_t buflen) {
	mSockAddrSize[i] = sizeof(mSockAddr[i]);
	int err = recvfrom(mSources[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr[i], &mSockAddrSize[i]);
	if (err>0){
		if (mFilter && mFilter->onIncomingTransfer(buf,buflen,(struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]) == false ){
			return 0;
		}
	}else if (err == -1) {
		mSockAddrSize[i] = 0;
	}
	return err;

}

int RelayChannel::send(int i, uint8_t *buf, size_t buflen) {
	int err;
	if (mSockAddrSize[i] > 0) {
		if (!mFilter || mFilter->onOutgoingTransfer(buf,buflen,(struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]) ){
			err = sendto(mSources[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]);
		}else err=buflen;//don't report error.
		return err;
	}
	return 0;

}

void RelayChannel::setFilter(shared_ptr<MediaFilter> filter){
	mFilter=filter;
}

RelaySession::RelaySession(MediaRelayServer *server) :
		mServer(server) {
	mLastActivityTime = getCurrentTime();
	mUsed = true;
}

shared_ptr<RelayChannel> RelaySession::addFront(const std::pair<std::string,std::string> &relayIps) {
	shared_ptr<RelayChannel> ms = make_shared<RelayChannel>(this, true, relayIps);
	LOGD("RelayChannel %p | Add | %s:%i <-> %i", ms.get(), ms->getIp().c_str(), ms->getPort(), ms->getRelayPort());
	mMutex.lock();
	mFronts.push_back(ms);
	mMutex.unlock();

	return ms;
}

void RelaySession::removeFront(const shared_ptr<RelayChannel> &ms) {
	LOGD("RelayChannel %p | Remove |  %s:%i <-> %i", ms.get(), ms->getIp().c_str(), ms->getPort(), ms->getRelayPort());
	mMutex.lock();
	mFronts.remove(ms);
	mMutex.unlock();
}

shared_ptr<RelayChannel> RelaySession::addBack(const std::pair<std::string,std::string> &relayIps) {
	shared_ptr<RelayChannel> ms = make_shared<RelayChannel>(this, false, relayIps);
	LOGD("RelayChannel %p | Add | %i <-> %s:%i", ms.get(), ms->getRelayPort(), ms->getIp().c_str(), ms->getPort());
	mMutex.lock();
	mBacks.push_back(ms);
	mMutex.unlock();
	return ms;
}

void RelaySession::removeBack(const shared_ptr<RelayChannel> &ms) {
	LOGD("RelayChannel %p | Remove | %i <-> %s:%i", ms.get(), ms->getRelayPort(), ms->getIp().c_str(), ms->getPort());
	mMutex.lock();
	mBacks.remove(ms);
	mMutex.unlock();
}

RelaySession::~RelaySession() {
}

void RelaySession::unuse() {
	mUsed = false;
}

bool RelaySession::checkMediaSources() {
	mMutex.lock();
	for (auto itb=mBacks.begin(); itb != mBacks.end(); ++itb) {
		if (!(*itb)->checkSocketsValid()) {
			mMutex.unlock();
			return false;
		}
	}
	for (auto itf=mFronts.begin(); itf != mFronts.end(); ++itf) {
		if (!(*itf)->checkSocketsValid()) {
			mMutex.unlock();
			return false;
		}
	}
	mMutex.unlock();
	return true;
}

void RelaySession::transfer(time_t curtime, const shared_ptr<RelayChannel> &org, int i) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	int recv_len;
	int send_len;

	mLastActivityTime = curtime;
	recv_len = org->recv(i, buf, maxsize);
	if (recv_len > 0) {
		if (org->getBehaviour() & RelayChannel::Send) {
			list<shared_ptr<RelayChannel>> list;
			if (org->isFront()) {
				list = mBacks;
			} else {
				list = mFronts;
			}
			mMutex.lock();
			auto it = list.begin();
			if (it != list.end()) {
				while (it != list.end()) {
					const shared_ptr<RelayChannel> &dest = (*it);
					if (dest->getBehaviour() & RelayChannel::Receive) {
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

RtpSession *MediaRelayServer::createRtpSession(const std::string & bindIp) {
	RtpSession *session = rtp_session_new(RTP_SESSION_SENDRECV);
#if ORTP_HAS_REUSEADDR
	rtp_session_set_reuseaddr(session, FALSE);
#endif
	for (int i = 0; i < 100; ++i) {
		int port = ((rand() % (mMaxPort - mMinPort)) + mMinPort) & 0xfffe;

#if ORTP_ABI_VERSION >= 9
		if (rtp_session_set_local_addr(session, bindIp.c_str(), port, port+1) == 0) {
#else
		if (rtp_session_set_local_addr(session, bindIp.c_str(), port) == 0) {
#endif
			return session;
		}
	}

	LOGE("Could not find a random port on interface %s !", bindIp.c_str());
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
	mMutex.lock();
	mSessions.push_back(s);
	mMutex.unlock();
	if (!mRunning)
		start();

	LOGD("There are now %i relay sessions running.", mSessions.size());
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
	list<shared_ptr<RelayChannel>> mediaSources;

	while (mRunning) {
		mMutex.lock();
		mediaSources.clear();
		pfds_size = 1;
		for (auto it = mSessions.begin(); it != mSessions.end(); ++it) {
			RelaySession *ptr = *it;
			ptr->getMutex().lock();

			const list<shared_ptr<RelayChannel>>& fronts = ptr->getFronts();
			for (auto it2 = fronts.begin(); it2 != fronts.end(); ++it2) {
				mediaSources.push_back(*it2);
			}

			const list<shared_ptr<RelayChannel>>& backs = ptr->getBacks();
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
			time_t curtime = getCurrentTime();
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
