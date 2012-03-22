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

class MediaSource {
public:
	MediaSource(RelaySession * relaySession, bool front);
	~MediaSource();

	typedef enum {
		None = 0,
		Receive = 1,
		Send = 2,
		All = 3,
	} BehaviourType;

	void set(const std::string &ip, int port);

	const std::string &getIp() const {
		return mIp;
	}

	int getPort() const {
		return mPort;
	}

	bool operator ==(const MediaSource &source) const {
		return mIp == source.mIp && mPort == source.mPort;
	}

	bool operator <(const MediaSource &source) const {
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

private:
	const bool mFront;
	BehaviourType mBehaviour;
	std::string mIp;
	int mPort;
	RtpSession *mSession;
	int mSources[2];
	struct sockaddr_storage mSockAddr[2];
	socklen_t mSockAddrSize[2];
	RelaySession *mRelaySession;
};

class RelaySession {
	friend class MediaRelayServer;
public:

	RelaySession(const std::string &bind_ip, const std::string & public_ip);
	~RelaySession();

	void fillPollFd(struct pollfd *tab);
	void transfer(time_t current, const std::shared_ptr<MediaSource> &org, int i);
	void unuse();
	const std::string & getPublicIp() const {
		return mPublicIp;
	}

	const std::string & getBindIp() const {
		return mBindIp;
	}

	const std::list<std::shared_ptr<MediaSource>>& getFronts() {
		return mFronts;
	}

	const std::list<std::shared_ptr<MediaSource>>& getBacks() {
		return mBacks;
	}

	bool isUsed() const {
		return mUsed;
	}

	time_t getLastActivityTime() const {
		return mLastActivityTime;
	}

	std::shared_ptr<MediaSource> addFront();
	void removeFront(const std::shared_ptr<MediaSource> &ms);

	std::shared_ptr<MediaSource> addBack();
	void removeBack(const std::shared_ptr<MediaSource> &ms);

private:
	Mutex mMutex;
	const std::string mBindIp;
	const std::string mPublicIp;
	time_t mLastActivityTime;
	bool_t mUsed;
	std::list<std::shared_ptr<MediaSource>> mFronts;
	std::list<std::shared_ptr<MediaSource>> mBacks;
};

class MediaRelayServer {
public:
	MediaRelayServer(const std::string &bind_ip, const std::string &public_ip);
	~MediaRelayServer();
	RelaySession *createSession();
	void update();

private:
	void start();
	void run();
	static void *threadFunc(void *arg);
	Mutex mMutex;
	std::list<RelaySession*> mSessions;
	std::string mBindIp;
	std::string mPublicIp;
	pthread_t mThread;
	int mCtlPipe[2];
	bool mRunning;
};

#endif
