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

struct MediaSource{
	MediaSource(){
		fd=-1;
		memset(&ss,0,sizeof(ss));
		slen=0;
	}
	int recv(uint8_t *buf, size_t buflen);
	int send(uint8_t *buf, size_t buflen);
	int fd;
	struct sockaddr_storage ss;
	socklen_t slen;
};

class RelaySession{
	public:
		RelaySession(const std::string &localip);
		~RelaySession();
		int getPorts(int ports[2])const;
		const std::string & getAddr()const;
		void fillPollFd(struct pollfd *tab);
		void transfer(time_t current, struct pollfd *tab);
		void unuse();
		bool isUsed()const{
			return mUsed;
		}
		time_t getLastActivityTime()const{
			return mLastActivityTime;
		}
	private:
		const std::string mLocalIp;
		RtpSession *mSession[2];
		MediaSource mSources[4]; //2 RTP sockets, 2 RTCP sockets
		time_t mLastActivityTime;
		bool_t mUsed;
};


class MediaRelayServer{
	public:
		MediaRelayServer(const std::string &local_ip);
		~MediaRelayServer();
		RelaySession *createSession();
	private:
		void start();
		void run();
		static void *threadFunc(void *arg);
		Mutex mMutex;
		std::list<RelaySession*> mSessions;
		std::string mLocalIp;
		pthread_t mThread;
		int mCtlPipe[2];
		bool mRunning;
};


#endif
