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
	void setDefaultSource(const char *ip, int port);
	std::string getAddress() {
		char buff[254];
		const char *ret = inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, buff, 254);
		if(ret != NULL)
			return std::string(buff);
		else
			return std::string("");
	}
	uint16_t getPort() {
		return ntohs(((struct sockaddr_in *)&ss)->sin_port);
	}
	int recv(uint8_t *buf, size_t buflen);
	int send(uint8_t *buf, size_t buflen);
	int fd;
	struct sockaddr_storage ss;
	socklen_t slen;
};

class RelaySession;

typedef struct
{
	RtpSession *mSession;
	MediaSource mSources[2];
	RelaySession *mRelay;
} RelaySessionRtp;

class RelaySession{

	public:
		RelaySession(const std::string &bind_ip, const std::string & public_ip);
		~RelaySession();
		std::shared_ptr<RelaySessionRtp> setFrontDefaultSource(const char *ip, int port);
		std::shared_ptr<RelaySessionRtp> createBackDefaultSource(const char *ip, int port);
		void setBackDefaultSource(std::shared_ptr<RelaySessionRtp>, const char *ip, int port);
		const std::string & getBindIp()const;
		const std::string & getPublicIp()const{
			return mPublicIp;
		}
		void update(time_t curtime);
		//void fillPollFd(struct pollfd *tab);
		//void transfer(time_t current, struct pollfd *tab);
		void transfer(time_t current, std::shared_ptr<RelaySessionRtp>, int i);
		void unuse();
		bool isUsed()const{
			return mUsed;
		}
		time_t getLastActivityTime()const{
			return mLastActivityTime;
		}
		std::shared_ptr<RelaySessionRtp> getFront() const {
			return mFront;
		}

		std::list<std::shared_ptr<RelaySessionRtp>> getBacks() const {
			return mBacks;
		}
	private:
		RelaySession();
		std::string mBindIp;
		std::string mPublicIp;
		std::shared_ptr<RelaySessionRtp> mFront;
		std::list<std::shared_ptr<RelaySessionRtp>> mBacks;
		time_t mLastActivityTime;
		bool_t mUsed;
};


class MediaRelayServer{
	public:
		MediaRelayServer(const std::string &bind_ip, const std::string &public_ip);
		~MediaRelayServer();
		RelaySession *createSession();
		RelaySession *addSession(RelaySession *s);
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
