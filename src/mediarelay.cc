/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <list>
#include <poll.h>
#include <sys/resource.h>

#include "agent.hh"
#include "mediarelay.hh"

using namespace std;
using namespace flexisip;

PollFd::PollFd(int init_size) : mCurSize(init_size) {
	mPfd = (struct pollfd*)malloc(mCurSize * sizeof(struct pollfd));
	mCurIndex = 0;
}

PollFd::~PollFd() {
	free(mPfd);
}

void PollFd::reset() {
	mCurIndex = 0;
}

int PollFd::addFd(int fd, unsigned int events) {
	if (mCurIndex == mCurSize) {
		mCurSize *= 2;
		mPfd = (struct pollfd*)realloc(mPfd, mCurSize * sizeof(struct pollfd));
	}
	mPfd[mCurIndex].fd = fd;
	mPfd[mCurIndex].events = events;
	mPfd[mCurIndex].revents = 0;
	return mCurIndex++;
}

unsigned int PollFd::getREvents(int index) const {
	if (index >= mCurSize) {
		throw FlexisipException{"bad access to pollfd table"};
	}
	return mPfd[index].revents;
}

RelayChannel::RelayChannel(RelaySession* relaySession, const RelayTransport& rt, bool preventLoops, Type type)
    : mRelayTransport(rt), mRemoteIp(std::string("undefined")), mDir(Dir::SendRecv), mType(type), mPacketsReceived{},
      mPacketsSent{} {
	mPfdIndex = -1;
	initializeRtpSession(relaySession);
	mSockAddrSize[0] = mSockAddrSize[1] = 0;
	mPreventLoop = preventLoops;
	mHasMultipleTargets = false;
	mDestAddrChanged = false;
	mRecvErrorCount[0] = mRecvErrorCount[1] = 0;
	mRemotePort[0] = mRemotePort[1] = -1;
	mIsOpen = false;
	mLogPrefix = LogManager::makeLogPrefixForInstance(this, typeToString(mType) + ".RelayChannel");
}

void RelayChannel::initializeRtpSession(RelaySession* relaySession) {
	string bindIp;
	if (mRelayTransport.mDualStackRequired) {
		bindIp = mRelayTransport.mIpv6BindAddress;
	} else {
		bindIp = mRelayTransport.mPreferredFamily == AF_INET6 ? mRelayTransport.mIpv6BindAddress
		                                                      : mRelayTransport.mIpv4BindAddress;
	}
	mSession = relaySession->getRelayServer()->createRtpSession(bindIp.c_str());
	mRelayTransport.mRtpPort = rtp_session_get_local_port(mSession);
	mRelayTransport.mRtcpPort = mRelayTransport.mRtpPort + 1;
	mSockets[0] = rtp_session_get_rtp_socket(mSession);
	mSockets[1] = rtp_session_get_rtcp_socket(mSession);
}

bool RelayChannel::checkSocketsValid() {
	return mSockets[0] != -1 && mSockets[1] != -1;
}

RelayChannel::~RelayChannel() {
	rtp_session_destroy(mSession);
}

const char* RelayChannel::dirToString(Dir dir) {
	switch (dir) {
		case Dir::SendOnly:
			return "SendOnly";
		case Dir::SendRecv:
			return "SendRecv";
		case Dir::Inactive:
			return "Inactive";
	}
	return "invalid";
}

string RelayChannel::typeToString(Type type) {
	switch (type) {
		case Type::Back:
			return "Back";
		case Type::Front:
			return "Front";
	}
	return "invalid";
}

void RelayChannel::setRemoteAddr(const string& ip, int rtp_port, int rtcp_port, Dir dir) {
	const string& localIp =
	    mRelayTransport.mPreferredFamily == AF_INET6 ? mRelayTransport.mIpv6Address : mRelayTransport.mIpv4Address;
	LOGD << "Now configured local=[" << localIp << "|" << mRelayTransport.mRtpPort << ":" << mRelayTransport.mRtcpPort
	     << "]  remote=[" << ip << "|" << rtp_port << ":" << rtcp_port << "] dir=[" << dirToString(dir) << "]";
	bool dest_ok = true;

	if (rtp_port > 0 && mPreventLoop) {
		if (ip == mRelayTransport.mIpv4Address || ip == mRelayTransport.mIpv6Address ||
		    ip == mRelayTransport.mIpv4BindAddress || ip == mRelayTransport.mIpv6BindAddress) {
			LOGD << "Wants to loop to local machine with ip [" << ip << "], not allowed";
			dest_ok = false;
		}
	}

	mRemotePort[0] = rtp_port;
	mRemotePort[1] = rtcp_port;
	mRemoteIp = ip;
	mDir = dir;

	if (dest_ok && rtp_port != 0) {
		struct addrinfo* res = NULL;
		struct addrinfo hints = {0};
		char portstr[20];
		int err;

		/* Mark channel as open since it is now given a destination address. */
		mIsOpen = true;

		if (mDestAddrChanged) {
			LOGD << "New destination address is being set but was fixed previously in this session, so ignoring this "
			        "request";
			return;
		}

		for (int i = 0; i < 2; ++i) {
			mRecvErrorCount[i] = 0;
			snprintf(portstr, sizeof(portstr), "%i", mRemotePort[i]);
			hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
			err = getaddrinfo(ip.c_str(), portstr, &hints, &res);
			if (err != 0) {
				LOGE << "Failed for " << ip << ":" << mRemotePort[i] << " : " << gai_strerror(err);
			} else {
				memcpy(&mSockAddr[i], res->ai_addr, res->ai_addrlen);
				mSockAddrSize[i] = res->ai_addrlen;
				freeaddrinfo(res);
			}
		}

	} else {
		/*case where client declined the stream (0 port in SDP) or destination address is invalid*/
		mDestAddrChanged = false;
		mSockAddrSize[0] = 0;
		mSockAddrSize[1] = 0;
		mIsOpen = false;
	}
}

void RelayChannel::setDirection(Dir value) {
	mDir = value;
}
RelayChannel::Dir RelayChannel::getDirection() const {
	return mDir;
}

void RelayChannel::fillPollFd(PollFd* pfd) {
	mPfdIndex = -1;
	if (mSockets[0] == -1) return; // no socket to monitor
	for (int i = 0; i < 2; ++i) {
		int index = pfd->addFd(mSockets[i], POLLIN);
		if (mPfdIndex == -1) mPfdIndex = index;
	}
}

bool RelayChannel::checkPollFd(const PollFd* pfd, int i) {
	if (mPfdIndex != -1) {
		return pfd->getREvents(mPfdIndex + i);
	}
	return false;
}

int RelayChannel::recv(int i, uint8_t* buf, size_t buflen, time_t curTime) {
	struct sockaddr_storage ss;
	socklen_t addrsize = sizeof(ss);

	int err = recvfrom(mSockets[i], buf, buflen, 0, (struct sockaddr*)&ss, &addrsize);
	if (err > 0) {
		mPacketsReceived[i]++;
		mRecvErrorCount[i] = 0;
		if (addrsize != mSockAddrSize[i] || memcmp(&ss, &mSockAddr[i], addrsize) != 0) {
			if (curTime - mSockAddrLastUseTime[i] > sDestinationSwitchTimeout) {
				char ipPort[128] = {0};
				string localIp = mRelayTransport.mPreferredFamily == AF_INET6
				                     ? (string("[") + mRelayTransport.mIpv6Address + string("]"))
				                     : mRelayTransport.mIpv4Address;
				bctbx_sockaddr_to_printable_ip_address((struct sockaddr*)&ss, addrsize, ipPort, sizeof(ipPort));
				LOGD << "Destination address updated for [" << (i == 0 ? "RTP" : "RTCP") << "]: local=[" << localIp
				     << ":" << (i == 0 ? mRelayTransport.mRtpPort : mRelayTransport.mRtcpPort) << "]  remote=["
				     << ipPort << "]";
				mSockAddrSize[i] = addrsize;
				memcpy(&mSockAddr[i], &ss, addrsize);
				mDestAddrChanged = true;
				mSockAddrLastUseTime[i] = curTime;
			} else {
				/* We receive from new remote address. Wait that previous remote address is not used for
				 * sDestinationSwitchTimeout seconds before deciding to switch to the new one.
				 */
			}
		} else {
			/* The remote address from which we are receiving packets hasn't changed, just update last use time. */
			mSockAddrLastUseTime[i] = curTime;
		}

		if (!mIsOpen || mDir == Dir::SendOnly || mDir == Dir::Inactive) {
			return 0;
		}
		if (mFilter &&
		    mFilter->onIncomingTransfer(buf, buflen, (struct sockaddr*)&mSockAddr[i], mSockAddrSize[i]) == false) {
			return 0;
		}
	} else if (err == -1) {
		LOGW << "Error receiving on port " << mRelayTransport.mRtpPort << " from " << mRemoteIp << ":" << mRemotePort[i]
		     << ": " << strerror(errno);
		if (errno == ECONNREFUSED) {
			mRecvErrorCount[i]++;
		}
	}
	return err;
}

int RelayChannel::send(int i, uint8_t* buf, size_t buflen) {
	int err = 0;
	/*if destination address is working mSockAddrSize>0*/
	if (mRemotePort[i] > 0 && mSockAddrSize[i] > 0 && mDir != Dir::Inactive && mRecvErrorCount[i] < sMaxRecvErrors &&
	    mIsOpen) {
		if (!mFilter || mFilter->onOutgoingTransfer(buf, buflen, (struct sockaddr*)&mSockAddr[i], mSockAddrSize[i])) {
			int localPort = (i == 0) ? mRelayTransport.mRtpPort : mRelayTransport.mRtcpPort;
			err = sendto(mSockets[i], buf, buflen, 0, (struct sockaddr*)&mSockAddr[i], mSockAddrSize[i]);
			mPacketsSent[i]++;
			if (err == -1) {
				LOGW << "Error sending " << buflen << " bytes (localport=" << localPort << " dest=" << mRemoteIp << ":"
				     << mRemotePort[i] << "): " << strerror(errno);
			} else if (err != (int)buflen) {
				LOGW << "Only " << err << " bytes sent over " << buflen << " bytes (localport=" << localPort
				     << " dest=" << mRemoteIp << ":" << mRemotePort[i] << ")";
			}
		}
	}
	return err;
}

void RelayChannel::setFilter(shared_ptr<MediaFilter> filter) {
	mFilter = filter;
}

RelaySession::RelaySession(MediaRelayServer* server, const string& frontId, const RelayTransport& rt)
    : mServer(server), mFrontChannelId(frontId) {
	mLastActivityTime = getCurrentTime();
	mUsed = true;
	mFrontChannel = make_shared<RelayChannel>(this, rt, mServer->loopPreventionEnabled(), RelayChannel::Type::Front);
	mLogPrefix = LogManager::makeLogPrefixForInstance(this, "RelaySession");
}

shared_ptr<RelayChannel> RelaySession::getChannel(const string& partyId, const string& trId) const {
	if (partyId == mFrontChannelId) return mFrontChannel;
	if (mSelectedBackChannel) return mSelectedBackChannel;

	shared_ptr<RelayChannel> ret;

	mMutex.lock();
	auto it = mPotentialBackChannels.find(trId);
	if (it != mPotentialBackChannels.end()) {
		ret = (*it).second;
	}
	mMutex.unlock();
	return ret;
}

std::shared_ptr<RelayChannel>
RelaySession::createBranch(const std::string& trId, const RelayTransport& rt, bool hasMultipleTargets) {
	shared_ptr<RelayChannel> ret;
	mMutex.lock();
	ret = make_shared<RelayChannel>(this, rt, mServer->loopPreventionEnabled(), RelayChannel::Type::Back);
	ret->setMultipleTargets(hasMultipleTargets);
	mPotentialBackChannels.insert(make_pair(trId, ret));
	mMutex.unlock();
	LOGD << ret->getLogPrefix() << " corresponding to transaction [" << trId << "] added";
	return ret;
}

void RelaySession::removeBranch(const std::string& trId) {
	bool removed = false;
	mMutex.lock();
	auto it = mPotentialBackChannels.find(trId);
	if (it != mPotentialBackChannels.end()) {
		removed = true;
		mPotentialBackChannels.erase(it);
	}
	mMutex.unlock();
	if (removed) {
		LOGD << "Branch corresponding to transaction [" << trId << "] removed";
	}
}

int RelaySession::getActiveBranchesCount() const {
	int count = 0;
	std::scoped_lock lock{mMutex};
	for (auto it = mPotentialBackChannels.begin(); it != mPotentialBackChannels.end(); ++it) {
		if ((*it).second->getRemoteRtpPort() > 0) count++;
	}
	if (mSelectedBackChannel && mSelectedBackChannel->getRemoteRtpPort() > 0) count++;
	LOGD << "getActiveBranchesCount(): " << count;
	return count;
}

int RelaySession::getBranchesCount() const {
	int count = 0;
	std::scoped_lock lock{mMutex};
	count = mPotentialBackChannels.size();
	if (mSelectedBackChannel) count++;
	LOGD << "getBranchesCount(): " << count;
	return count;
}

void RelaySession::setEstablished(const std::string& tr_id) {
	if (mSelectedBackChannel) return;
	shared_ptr<RelayChannel> winner = getChannel("", tr_id);
	if (winner) {
		LOGD << "Is established";
		mMutex.lock();
		mSelectedBackChannel = winner;
		mPotentialBackChannels.clear();
		mMutex.unlock();
	} else LOGE << "Is with from an unknown branch [" << tr_id << "]";
}

void RelaySession::fillPollFd(PollFd* pfd) {
	mMutex.lock();

	if (mFrontChannel) mFrontChannel->fillPollFd(pfd);
	if (mSelectedBackChannel) mSelectedBackChannel->fillPollFd(pfd);
	else {
		for (auto it = mPotentialBackChannels.begin(); it != mPotentialBackChannels.end(); ++it) {
			(*it).second->fillPollFd(pfd);
		}
	}
	mMutex.unlock();
}

void RelaySession::checkPollFd(const PollFd* pfd, time_t curtime) {
	int i;
	mMutex.lock();
	for (i = 0; i < 2; ++i) {
		if (mFrontChannel && mFrontChannel->checkPollFd(pfd, i)) transfer(curtime, mFrontChannel, i);
		if (!mSelectedBackChannel) {
			for (auto it = mPotentialBackChannels.begin(); it != mPotentialBackChannels.end(); ++it) {
				shared_ptr<RelayChannel> chan = (*it).second;
				if (chan->checkPollFd(pfd, i)) transfer(curtime, chan, i);
			}
		} else if (mSelectedBackChannel->checkPollFd(pfd, i)) {
			transfer(curtime, mSelectedBackChannel, i);
		}
	}
	mMutex.unlock();
}

RelaySession::~RelaySession() {
	LOGD << "Destroyed instance";
}

struct Statistics {
	static constexpr std::string_view mLogPrefix{"Statistics"};

	int port = 0;
	uint64_t recv = 0;
	uint64_t sent = 0;

	static void log(const Statistics st[2], const std::string& identifier) {
		LOGD << identifier << " statistics:\n"
		     << "RTP port: " << st[0].port << "\tReceived packets: " << st[0].recv << "\tSent packets: " << st[0].sent
		     << "\n"
		     << "RTCP port: " << st[1].port << "\tReceived packets: " << st[1].recv << "\tSent packets: " << st[1].sent
		     << "\n";
	}
};

void RelaySession::unuse() {
	Statistics front[2], back[2];

	LOGD << "Terminated";

	/* Do not log while holding a mutex, so copy out statistics first, and then display them. */

	mMutex.lock();
	mUsed = false;
	for (int componentID = 0; componentID < 2; ++componentID) {
		if (mFrontChannel) {
			front[componentID].port = componentID == 0 ? mFrontChannel->getRelayTransport().mRtpPort
			                                           : mFrontChannel->getRelayTransport().mRtcpPort;
			front[componentID].recv = mFrontChannel->getReceivedPackets(componentID);
			front[componentID].sent = mFrontChannel->getSentPackets(componentID);
		}
		if (mSelectedBackChannel) {
			back[componentID].port = componentID == 0 ? mSelectedBackChannel->getRelayTransport().mRtpPort
			                                          : mSelectedBackChannel->getRelayTransport().mRtcpPort;
			back[componentID].recv = mSelectedBackChannel->getReceivedPackets(componentID);
			back[componentID].sent = mSelectedBackChannel->getSentPackets(componentID);
		}
	}
	mFrontChannel.reset();
	mPotentialBackChannels.clear();
	mSelectedBackChannel.reset();
	mMutex.unlock();

	if (front[0].port != 0) {
		Statistics::log(front, "Caller side");
	}
	if (back[0].port != 0) {
		Statistics::log(back, "Callee side");
	}
}

bool RelaySession::checkChannels() {
	mMutex.lock();
	for (auto itb = mPotentialBackChannels.begin(); itb != mPotentialBackChannels.end(); ++itb) {
		if (!(*itb).second->checkSocketsValid()) {
			mMutex.unlock();
			return false;
		}
	}
	if (!mFrontChannel->checkSocketsValid()) {
		mMutex.unlock();
		return false;
	}
	mMutex.unlock();
	return true;
}

void RelaySession::transfer(time_t curtime, const shared_ptr<RelayChannel>& chan, int i) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	int recv_len;

	mLastActivityTime = curtime;
	recv_len = chan->recv(i, buf, maxsize, curtime);
	if (recv_len > 0) {
		if (chan == mFrontChannel) {
			if (mSelectedBackChannel) {
				mSelectedBackChannel->send(i, buf, recv_len);
			} else {
				for (auto it = mPotentialBackChannels.begin(); it != mPotentialBackChannels.end(); ++it) {
					shared_ptr<RelayChannel> dest = (*it).second;
					dest->send(i, buf, recv_len);
				}
			}
		} else {
			mFrontChannel->send(i, buf, recv_len);
		}
	}
}

MediaRelayServer::MediaRelayServer(MediaRelay* module) : mModule(module) {
	mRunning = false;
	mSessionsCount = 0;
	if (pipe(mCtlPipe) == -1) throw FlexisipException{"could not create MediaRelayServer control pipe"};
}

Agent* MediaRelayServer::getAgent() {
	return mModule->getAgent();
}

RtpSession* MediaRelayServer::createRtpSession(const std::string& bindIp) {
	RtpSession* session = rtp_session_new(RTP_SESSION_SENDRECV);
#if ORTP_HAS_REUSEADDR
	rtp_session_set_reuseaddr(session, FALSE);
#endif
	for (int i = 0; i < 100; ++i) {
		int port = ((rand() % (mModule->mMaxPort - mModule->mMinPort)) + mModule->mMinPort) & 0xfffe;

#if ORTP_ABI_VERSION >= 9
		if (rtp_session_set_local_addr(session, bindIp.c_str(), port, port + 1) == 0) {
#else
		if (rtp_session_set_local_addr(session, bindIp.c_str(), port) == 0) {
#endif
			return session;
		}
	}

	LOGE << "Could not find a random port on interface " << bindIp;
	return session;
}

void MediaRelayServer::start() {
	mRunning = true;
	pthread_create(&mThread, NULL, &MediaRelayServer::threadFunc, this);
}

MediaRelayServer::~MediaRelayServer() {
	if (mRunning) {
		mRunning = false;
		if (write(mCtlPipe[1], "e", 1) == -1) LOGE << "Fail to write to control pipe";
		pthread_join(mThread, NULL);
	}
	mSessions.clear();
	mSessionsCount = 0;
	close(mCtlPipe[0]);
	close(mCtlPipe[1]);
}

shared_ptr<RelaySession> MediaRelayServer::createSession(const std::string& frontId,
                                                         const RelayTransport& frontRelayTransport) {
	shared_ptr<RelaySession> s = make_shared<RelaySession>(this, frontId, frontRelayTransport);
	mMutex.lock();
	mSessions.push_back(s);
	mSessionsCount++;
	mMutex.unlock();
	if (!mRunning) start();

	LOGI << "There are now " << mSessionsCount << " relay sessions running";
	/*write to the control pipe to wakeup the server thread */
	update();
	return s;
}

void MediaRelayServer::update() {
	/*write to the control pipe to wakeup the server thread */
	if (write(mCtlPipe[1], "e", 1) == -1) LOGE << "Fail to write to control pipe";
}

static void set_high_prio() {
	struct sched_param param;
	int policy = SCHED_RR;
	int result = 0;
	int max_prio;

	memset(&param, 0, sizeof(param));

	max_prio = sched_get_priority_max(policy);
	param.sched_priority = max_prio;
	if ((result = pthread_setschedparam(pthread_self(), policy, &param))) {
		if (result == EPERM) {
			/*
			    The linux kernel has
			    sched_get_priority_max(SCHED_OTHER)=sched_get_priority_max(SCHED_OTHER)=0.
			    As long as we can't use SCHED_RR or SCHED_FIFO, the only way to increase priority of a calling thread is
			   to use setpriority().
			*/
			if (setpriority(PRIO_PROCESS, 0, -20) == -1) {
				LOGD_CTX("MediaRelayServer") << "setpriority() failed: " << strerror(errno) << ", nevermind";
			} else {
				LOGI_CTX("MediaRelayServer") << "Priority increased to maximum";
			}
		} else LOGW_CTX("MediaRelayServer") << "pthread_setschedparam failed: " << strerror(result);
	} else {
		LOGI_CTX("MediaRelayServer") << "Priority set to [" << (policy == SCHED_FIFO ? "SCHED_FIFO" : "SCHED_RR")
		                             << "] and value [" << param.sched_priority << "]";
	}
}

void MediaRelayServer::run() {
	PollFd pfd(512);
	int ctl_index;
	int err;

	set_high_prio();
	while (mRunning) {
		pfd.reset();
		// fill the pollfd table
		mMutex.lock();
		for (auto it = mSessions.begin(); it != mSessions.end(); ++it) {
			if ((*it)->isUsed()) (*it)->fillPollFd(&pfd);
		}
		mMutex.unlock();

		ctl_index = pfd.addFd(mCtlPipe[0], POLLIN);

		err = poll(pfd.getPfd(), pfd.getCurIndex(), 1000);
		if (err > 0) {
			// examine pollfd results
			if (pfd.getREvents(ctl_index) & POLLIN) {
				char tmp;
				if (read(mCtlPipe[0], &tmp, 1) == -1) {
					LOGE << "Fail to read from control pipe";
				}
			}
			time_t curtime = getCurrentTime();
			mMutex.lock();
			for (auto it = mSessions.begin(); it != mSessions.end();) {
				if (!(*it)->isUsed()) {
					it = mSessions.erase(it);
					mSessionsCount--;
					LOGI << "There are now " << mSessionsCount << " relay sessions running";
				} else {
					(*it)->checkPollFd(&pfd, curtime);
					++it;
				}
			}
			mMutex.unlock();
		}
	}
}

void* MediaRelayServer::threadFunc(void* arg) {
	MediaRelayServer* zis = (MediaRelayServer*)arg;
	zis->run();
	return NULL;
}