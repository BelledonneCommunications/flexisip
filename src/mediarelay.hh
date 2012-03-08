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

class MediaSource {
public:
	MediaSource(const std::string &ip, int port);
	MediaSource(const struct sockaddr_storage &sockaddr, socklen_t sockaddr_size);
	const std::string &getIp() const {
		return mIp;
	}

	int getPort() const {
		return mPort;
	}

	const struct sockaddr_storage &getSockAddr() const {
		return mSockAddr;
	}
	socklen_t getSockAddrSize() const {
		return mSockAddrSize;
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

private:
	std::string mIp;
	int mPort;
	struct sockaddr_storage mSockAddr;
	socklen_t mSockAddrSize;
};

class RelaySession {
public:
	RelaySession(const std::string &bind_ip, const std::string & public_ip);
	~RelaySession();

        int getFrontPort()const;
        int getBackPort()const;
	void fillPollFd(struct pollfd *tab);
	void transfer(time_t current, struct pollfd *tab);
	void unuse();
	const std::string & getPublicIp() const {
		return mPublicIp;
	}
	bool isUsed() const {
		return mUsed;
	}
	time_t getLastActivityTime() const {
		return mLastActivityTime;
	}


	void addFront(const std::string &ip, int port);
	void addBack(const std::string &ip, int port);
	void removeFront(const std::string &ip, int port);
	void removeBack(const std::string &ip, int port);
private:
	void addFront(const MediaSource&src);
	void addBack(const MediaSource&src);

	Mutex mMutex;
	std::list<MediaSource> mFront;
	std::list<MediaSource> mBack;
	const std::string mBindIp;
	const std::string mPublicIp;
	RtpSession *mSession[2];
	int mSources[4]; //2 RTP sockets, 2 RTCP sockets
	time_t mLastActivityTime;
	bool_t mUsed;
};

class MediaRelayServer {
public:
	MediaRelayServer(const std::string &bind_ip, const std::string &public_ip);
	~MediaRelayServer();
	RelaySession *createSession();
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
