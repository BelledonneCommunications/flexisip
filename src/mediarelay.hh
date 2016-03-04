/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#ifndef mediarelay_hh
#define mediarelay_hh

#include "module.hh"
#include "agent.hh"
#include "callstore.hh"
#include "sdp-modifier.hh"
#include <ortp/rtpsession.h>

class RelayedCall;
class MediaRelayServer;

class MediaRelay : public Module, protected ModuleToolbox {
	friend class MediaRelayServer;
	friend class RelayedCall;

  public:
	MediaRelay(Agent *ag);
	~MediaRelay();
	virtual void onLoad(const GenericStruct *modconf);
	virtual void onUnload();
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev) throw (FlexisipException);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev) throw (FlexisipException);
	virtual void onIdle();

  protected:
	virtual void onDeclare(GenericStruct *mc);

  private:
	void createServers();
	bool processNewInvite(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction> &transaction,
						  const shared_ptr<RequestSipEvent> &ev);
	void processResponseWithSDP(const shared_ptr<RelayedCall> &c, const shared_ptr<OutgoingTransaction> &transaction,
								const shared_ptr<MsgSip> &msgSip);
	void configureContext(shared_ptr<RelayedCall> &c);
	CallStore *mCalls;
	vector<shared_ptr<MediaRelayServer>> mServers;
	size_t mCurServer;
	string mSdpMangledParam;
	int mH264FilteringBandwidth;
	bool mH264DecimOnlyIfLastProxy;

	StatCounter64 *mCountCalls;
	StatCounter64 *mCountCallsFinished;
	int mH264Decim;
	int mMaxCalls;
	int mMinPort, mMaxPort;
	int mMaxRelayedEarlyMedia;
	bool mDropTelephoneEvent;
	bool mByeOrphanDialogs;
	bool mEarlyMediaRelaySingle;
	bool mPreventLoop;
	bool mForceRelayForNonIceTargets;
	static ModuleInfo<MediaRelay> sInfo;
};

class RelaySession;
class MediaRelay;

class PollFd {
  public:
	PollFd(int init_size);
	~PollFd();
	void reset();
	int addFd(int fd, unsigned int events);
	unsigned int getREvents(int index) const;
	struct pollfd *getPfd() {
		return mPfd;
	}
	int getCurIndex() const {
		return mCurIndex;
	}

  private:
	struct pollfd *mPfd;
	int mCurIndex;
	int mCurSize;
};

class MediaRelayServer {
	friend class RelayedCall;

  public:
	MediaRelayServer(MediaRelay *module);
	~MediaRelayServer();
	std::shared_ptr<RelaySession> createSession(const std::string &frontId,
												const std::pair<std::string, std::string> &frontRelayIps);
	void update();
	Agent *getAgent();
	RtpSession *createRtpSession(const std::string &bindIp);
	void enableLoopPrevention(bool val);
	bool loopPreventionEnabled() const {
		return mModule->mPreventLoop;
	}

  private:
	void start();
	void run();
	static void *threadFunc(void *arg);
	Mutex mMutex;
	std::list<std::shared_ptr<RelaySession>> mSessions;
	MediaRelay *mModule;
	pthread_t mThread;
	int mCtlPipe[2];
	bool mRunning;
	friend class RelayChannel;
};

class RelayChannel;

/**
 * The RelaySession holds context for relaying for a single media stream, RTP and RTCP included.
 * It has one front channel (the one to communicate with the party that generated the SDP offer,
 * and one or several back channels, created by each party responding to the other with eventual early-media offers.
 * Each back channel is identified with a unique transaction id.
 * The front channel is identified by its from-tag.
 * When the call is established, a single back channel remains active, the one corresponding to the party that took the
 *call.
**/
class RelaySession : public std::enable_shared_from_this<RelaySession> {
  public:
	RelaySession(MediaRelayServer *server, const std::string &frontId,
				 const std::pair<std::string, std::string> &frontRelayIps);
	~RelaySession();

	void fillPollFd(PollFd *pfd);
	void checkPollFd(const PollFd *pfd, time_t curtime);
	void unuse();
	int getActiveBranchesCount();

	bool isUsed() const {
		return mUsed;
	}

	time_t getLastActivityTime() const {
		return mLastActivityTime;
	}

	/**
	 * Called each time an INVITE is forked
	 */
	std::shared_ptr<RelayChannel> createBranch(const std::string &trId,
											   const std::pair<std::string, std::string> &relayIps);
	void removeBranch(const std::string &trId);

	/**
	 * Called when the call is established, to remove unnecessary back channels
	**/
	void setEstablished(const std::string &tr_id);

	std::shared_ptr<RelayChannel> getChannel(const std::string &partyId, const std::string &trId);

	MediaRelayServer *getRelayServer() {
		return mServer;
	}
	bool checkChannels();

  private:
	void transfer(time_t current, const std::shared_ptr<RelayChannel> &org, int i);
	Mutex mMutex;
	MediaRelayServer *mServer;
	time_t mLastActivityTime;
	std::string mFrontId;
	std::shared_ptr<RelayChannel> mFront;
	std::map<std::string, std::shared_ptr<RelayChannel>> mBacks;
	std::shared_ptr<RelayChannel> mBack;
	bool_t mUsed;
};

class MediaFilter {
  public:
	/// Should return false if the incoming packet must not be transfered.
	virtual bool onIncomingTransfer(uint8_t *data, size_t size, const sockaddr *addr, socklen_t addrlen) = 0;
	/// Should return false if the packet output must not be sent.
	virtual bool onOutgoingTransfer(uint8_t *data, size_t size, const sockaddr *addr, socklen_t addrlen) = 0;
};

class RelayChannel : public SdpMasqueradeContext{
  public:
	enum Dir { SendOnly, SendRecv, Inactive };

	RelayChannel(RelaySession *relaySession, const std::pair<std::string, std::string> &relayIps, bool preventLoops);
	~RelayChannel();
	bool checkSocketsValid();
	void setRemoteAddr(const std::string &ip, int port, Dir dir);
	const std::string &getRemoteIp() const {
		return mRemoteIp;
	}
	int getRemotePort() const {
		return mRemotePort;
	}
	const std::string &getLocalIp() const {
		return mLocalIp;
	}
	int getLocalPort() const {
		return rtp_session_get_local_port(mSession);
	}
	int recv(int i, uint8_t *buf, size_t size);
	int send(int i, uint8_t *buf, size_t size);
	void fillPollFd(PollFd *pfd);
	bool checkPollFd(const PollFd *pfd, int i);
	void setFilter(std::shared_ptr<MediaFilter> filter);
	uint64_t getReceivedPackets() const {
		return mPacketsReceived;
	}
	uint64_t getSentPackets() const {
		return mPacketsSent;
	}
	static const char *dirToString(Dir dir);

  private:
	Dir mDir;
	std::string mLocalIp;
	std::string mRemoteIp;
	int mRemotePort;
	RtpSession *mSession;
	int mSockets[2];
	struct sockaddr_storage mSockAddr[2];
	socklen_t mSockAddrSize[2];
	std::shared_ptr<MediaFilter> mFilter;
	int mPfdIndex;
	uint64_t mPacketsSent;
	uint64_t mPacketsReceived;
	bool mPreventLoop;
};

#endif
