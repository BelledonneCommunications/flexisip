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

#ifndef mediarelay_hh
#define mediarelay_hh

#include "agent.hh"
#include <ortp/rtpsession.h>

class RelaySession;

class MediaRelayServer {
public:
	MediaRelayServer(Agent *agent);
	~MediaRelayServer();
	RelaySession *createSession();
	void update();
	Agent *getAgent();
	RtpSession *createRtpSession(const std::string & bindIp);
private:
	void start();
	void run();
	static void *threadFunc(void *arg);
	Mutex mMutex;
	std::list<RelaySession*> mSessions;
	Agent *mAgent;
	int mMinPort;
	int mMaxPort;

	pthread_t mThread;
	int mCtlPipe[2];
	bool mRunning;

	friend class RelayChannel;
	//int ,
};

class RelayChannel;


class RelaySession {
public:

	RelaySession(MediaRelayServer *server);
	~RelaySession();

	void fillPollFd(struct pollfd *tab);
	void transfer(time_t current, const std::shared_ptr<RelayChannel> &org, int i);
	void unuse();

	const std::list<std::shared_ptr<RelayChannel>>& getFronts() {
		return mFronts;
	}

	const std::list<std::shared_ptr<RelayChannel>>& getBacks() {
		return mBacks;
	}

	bool isUsed() const {
		return mUsed;
	}

	time_t getLastActivityTime() const {
		return mLastActivityTime;
	}

	std::shared_ptr<RelayChannel> addFront(const std::pair<std::string,std::string> & relayIps);
	void removeFront(const std::shared_ptr<RelayChannel> &ms);

	std::shared_ptr<RelayChannel> addBack(const std::pair<std::string,std::string> & relayIps);
	void removeBack(const std::shared_ptr<RelayChannel> &ms);

	Mutex &getMutex() {
		return mMutex;
	}

	MediaRelayServer *getRelayServer() {
		return mServer;
	}
	bool checkMediaSources();

private:
	Mutex mMutex;
	MediaRelayServer *mServer;
	time_t mLastActivityTime;
	bool_t mUsed;
	std::list<std::shared_ptr<RelayChannel>> mFronts;
	std::list<std::shared_ptr<RelayChannel>> mBacks;
};

class MediaFilter{
public:
	///Should return false if the incoming packet must not be transfered.
	virtual bool onIncomingTransfer(uint8_t *data, size_t size, const sockaddr *addr, socklen_t addrlen)=0;
	///Should return false if the packet output must not be sent.
	virtual bool onOutgoingTransfer(uint8_t *data, size_t size, const sockaddr *addr, socklen_t addrlen)=0;
};



class RelayChannel {
public:
	RelayChannel(RelaySession * relaySession, bool front, const std::pair<std::string,std::string> &relayIps);
	~RelayChannel();

	typedef enum {
		None = 0,
		Receive = 1,
		Send = 2,
		All = 3,
	} BehaviourType;

	bool checkSocketsValid();

	void set(const std::string &ip, int port);

	const std::string &getIp() const {
		return mIp;
	}

	const std::string &getPublicIp() const {
		return mPublicIp;
	}

	int getPort() const {
		return mPort;
	}

	bool operator ==(const RelayChannel &source) const {
		return mIp == source.mIp && mPort == source.mPort;
	}

	bool operator <(const RelayChannel &source) const {
		if (mIp == source.mIp) {
			return mPort < source.mPort;
		}
		return mIp < source.mIp;
	}

	int recv(int i, uint8_t *buf, size_t size);
	int send(int i, uint8_t *buf, size_t size);

	void fillPollFd(struct pollfd *tab);

	int getRelayPort() const {
		return rtp_session_get_local_port(mSession);
	}

	const BehaviourType &getBehaviour() const{
		return mBehaviour;
	}

	void setBehaviour(const BehaviourType &behaviour);

	bool isFront() {
		return mFront;
	}

	RelaySession *getRelaySession() {
		return mRelaySession;
	}
	
	void setFilter(std::shared_ptr<MediaFilter> filter);

private:
	const bool mFront;
	BehaviourType mBehaviour;
	std::string mPublicIp;
	std::string mIp;
	int mPort;
	RtpSession *mSession;
	int mSources[2];
	struct sockaddr_storage mSockAddr[2];
	socklen_t mSockAddrSize[2];
	RelaySession *mRelaySession;
	std::shared_ptr<MediaFilter> mFilter;
};

#endif

