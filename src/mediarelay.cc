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
#include <sys/time.h>
#include <sys/resource.h>

#include <algorithm>
#include <list>


using namespace ::std;


PollFd::PollFd(int init_size) : mCurSize(init_size){
	mPfd=(struct pollfd*)malloc(mCurSize*sizeof(struct pollfd));
	mCurIndex=0;
}

PollFd::~PollFd(){
	free(mPfd);
}

void PollFd::reset(){
	mCurIndex=0;
}

int PollFd::addFd(int fd, unsigned int events){
	if (mCurIndex==mCurSize){
		mCurSize*=2;
		mPfd=(struct pollfd*)realloc(mPfd,mCurSize*sizeof(struct pollfd));
	}
	mPfd[mCurIndex].fd=fd;
	mPfd[mCurIndex].events=events;
	mPfd[mCurIndex].revents=0;
	return mCurIndex++;
}

unsigned int PollFd::getREvents(int index)const{
	if (index>=mCurSize){
		LOGA("Bad access to pollfd table.");
		return 0;
	}
	return mPfd[index].revents;
}


RelayChannel::RelayChannel(RelaySession* relaySession, const std::pair<std::string,std::string> &relayIps) :
		 mDir(SendRecv), mLocalIp(relayIps.first), mRemoteIp(std::string("undefined")), mRemotePort(-1){
	mPfdIndex=-1;
	mSession = relaySession->getRelayServer()->createRtpSession(relayIps.second);
	mSockets[0] = rtp_session_get_rtp_socket(mSession);
	mSockets[1] = rtp_session_get_rtcp_socket(mSession);
	mPacketsReceived=0;
	mPacketsSent=0;
}

bool RelayChannel::checkSocketsValid() {
	return mSockets[0] != -1 && mSockets[1] != -1;
}

RelayChannel::~RelayChannel() {
	rtp_session_destroy(mSession);
}

const char *RelayChannel::dirToString(Dir dir){
	switch(dir){
		case SendOnly:
			return "SendOnly";
		case SendRecv:
			return "SendRecv";
	}
	return "invalid";
}

void RelayChannel::setRemoteAddr(const string &ip, int port, Dir dir) {
	LOGD("RelayChannel [%p] is now configured local=[%s:%i]  remote=[%s:%i] dir=[%s]", 
	     this, getLocalIp().c_str(), getLocalPort(), ip.c_str(), port, dirToString(dir));
	
	mRemotePort = port;
	mRemoteIp = ip;
	mDir=dir;
	
	if (port!=0){
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
	}else{
		/*case where client declined the stream (0 port in SDP)*/
		mSockAddrSize[0]=0;
		mSockAddrSize[1]=0;
	}
}

void RelayChannel::fillPollFd(PollFd *pfd) {
	mPfdIndex=-1;
	if (mSockets[0]==-1) return ; //no socket to monitor
	for (int i = 0; i < 2; ++i) {
		int index=pfd->addFd(mSockets[i],POLLIN);
		if (mPfdIndex==-1) mPfdIndex=index;
	}
}

bool RelayChannel::checkPollFd(const PollFd *pfd, int i){
	if (mPfdIndex!=-1){
		return pfd->getREvents(mPfdIndex+i);
	}
	return false;
}

int RelayChannel::recv(int i, uint8_t *buf, size_t buflen) {
	socklen_t addrsize=sizeof(mSockAddr[i]);
	int err = recvfrom(mSockets[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr[i], &addrsize);
	if (err>0){
		mPacketsReceived++;
		mSockAddrSize[i] = addrsize;
		if (mDir==SendOnly) {
			LOGD("ignored packet");
			return 0;
		}
		if (mFilter && mFilter->onIncomingTransfer(buf,buflen,(struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]) == false ){
			return 0;
		}
	}else if (err == -1) {
		LOGW("Error receiving on port %i from %s:%i: %s",getLocalPort(), mRemoteIp.c_str(), mRemotePort+i, strerror(errno));
		if (errno==ECONNREFUSED){
			/*this will avoid to continue sending if there are ICMP errors*/
			mSockAddrSize[i] = 0;
		}
	}
	return err;

}

int RelayChannel::send(int i, uint8_t *buf, size_t buflen) {
	int err=0;
	/*if destination address is working mSockAddrSize>0*/
	if (mRemotePort>0 && mSockAddrSize[i] > 0) {
		if (!mFilter || mFilter->onOutgoingTransfer(buf,buflen,(struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]) ){
			err = sendto(mSockets[i], buf, buflen, 0, (struct sockaddr*) &mSockAddr[i], mSockAddrSize[i]);
			mPacketsSent++;
			if (err==-1){
				LOGW("Error sending %i bytes (localport=%i dest=%s:%i) : %s",(int) buflen, getLocalPort() + i, mRemoteIp.c_str(), mRemotePort, strerror(errno));
			}else if (err != (int)buflen) {
				LOGW("Only %i bytes sent over %i bytes (localport=%i dest=%s:%i)", err, (int)buflen, getLocalPort() + i, mRemoteIp.c_str(), mRemotePort+i);
			}
		}
	}else{
		LOGW("Destination not valid.");
	}
	return err;
}

void RelayChannel::setFilter(shared_ptr<MediaFilter> filter){
	mFilter=filter;
}

RelaySession::RelaySession(MediaRelayServer *server, const string &frontId, const std::pair<std::string,std::string> &relayIps) :
		mServer(server),mFrontId(frontId) {
	mLastActivityTime = getCurrentTime();
	mUsed = true;
	mFront=make_shared<RelayChannel>(this,relayIps);
}

shared_ptr<RelayChannel> RelaySession::getChannel(const string &partyId, const string &trId){
	if (partyId==mFrontId) return mFront;
	if (mBack) return mBack;
	
	shared_ptr<RelayChannel> ret;
	
	mMutex.lock();
	auto it=mBacks.find(trId);
	if (it!=mBacks.end()){
		ret=(*it).second;
	}
	mMutex.unlock();
	return ret;
}

std::shared_ptr<RelayChannel> RelaySession::createBranch(const std::string &trId, const std::pair<std::string,std::string> &relayIps){
	shared_ptr<RelayChannel> ret;
	mMutex.lock();
	ret=make_shared<RelayChannel>(this, relayIps);
	mBacks.insert(make_pair(trId,ret));
	mMutex.unlock();
	LOGD("RelaySession [%p]: branch corresponding to transaction [%s] added.",this,trId.c_str());
	return ret;
}

void RelaySession::removeBranch(const std::string &trId){
	bool removed=false;
	mMutex.lock();
	auto it=mBacks.find(trId);
	if (it!=mBacks.end()){
		removed=true;
		mBacks.erase(it);
	}
	mMutex.unlock();
	if (removed) LOGD("RelaySession [%p]: branch corresponding to transaction [%s] removed.",this,trId.c_str());
}

void RelaySession::setEstablished(const std::string &tr_id){
	if (mBack) return;
	shared_ptr<RelayChannel> winner=getChannel("",tr_id);
	if (winner){
		LOGD("RelaySession [%p] is established.",this);
		mMutex.lock();
		mBack=winner;
		mBacks.clear();
		mMutex.unlock();
	}else LOGE("RelaySession [%p] is with from an unknown branch [%s].",this,tr_id.c_str());
}

void RelaySession::fillPollFd(PollFd* pfd) {
	mMutex.lock();
	
	if (mFront) mFront->fillPollFd(pfd);
	if (mBack) mBack->fillPollFd(pfd);
	else{
		for(auto it=mBacks.begin();it!=mBacks.end();++it){
			(*it).second->fillPollFd(pfd);
		}
	}
	mMutex.unlock();
}

void RelaySession::checkPollFd(const PollFd *pfd, time_t curtime){
	int i;
	mMutex.lock();
	for(i=0;i<2;++i){
		if (mFront && mFront->checkPollFd(pfd,i))
			transfer(curtime,mFront,i);
		if (!mBack){
			for(auto it=mBacks.begin();it!=mBacks.end();++it){
				shared_ptr<RelayChannel> chan=(*it).second;
				if (chan->checkPollFd(pfd,i))
					transfer(curtime,chan,i);
			}
		}else if (mBack->checkPollFd(pfd,i)){
			transfer(curtime,mBack,i);
		}
	}
	mMutex.unlock();
}


RelaySession::~RelaySession() {
	LOGD("RelaySession %p destroyed", this);
}

void RelaySession::unuse() {
	struct statistics{
		int port;
		unsigned long recv;
		unsigned long sent;
	}front={0}, back={0};
	
	LOGD("RelaySession [%p] terminated.",this);
	
	mMutex.lock();
	mUsed = false;
	if (mFront){
		front.port=mFront->getLocalPort();
		front.recv=mFront->getReceivedPackets();
		front.sent=mFront->getSentPackets();
	}
	if (mBack){
		back.port=mBack->getLocalPort();
		back.recv=mBack->getReceivedPackets();
		back.sent=mBack->getSentPackets();
	}
	mFront.reset();
	mBacks.clear();
	mBack.reset();
	mMutex.unlock();
	
	/*do not log while holding a mutex*/
	if (front.port>0) LOGD("Front on port [%i] received [%lu] and sent [%lu] packets.",front.port, front.recv, front.sent);
	if (back.port>0) LOGD("Back on port [%i] received [%lu] and sent [%lu] packets.",back.port, back.recv, back.sent);
}

bool RelaySession::checkChannels() {
	mMutex.lock();
	for (auto itb=mBacks.begin(); itb != mBacks.end(); ++itb) {
		if (!(*itb).second->checkSocketsValid()) {
			mMutex.unlock();
			return false;
		}
	}
	if (!mFront->checkSocketsValid()) {
		mMutex.unlock();
		return false;
	}
	mMutex.unlock();
	return true;
}

void RelaySession::transfer(time_t curtime, const shared_ptr<RelayChannel> &chan, int i) {
	uint8_t buf[1500];
	const int maxsize = sizeof(buf);
	int recv_len;
	
	mLastActivityTime = curtime;
	recv_len = chan->recv(i, buf, maxsize);
	if (recv_len > 0) {
		if (chan==mFront) {
			if (mBack){
				mBack->send(i,buf,recv_len);
			}else{
				for (auto it=mBacks.begin();it != mBacks.end();++it) {
					shared_ptr<RelayChannel> dest = (*it).second;
					dest->send(i,buf,recv_len);
				}
			}
		}else {
			mFront->send(i,buf,recv_len);
		}
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
	mSessions.clear();
	close(mCtlPipe[0]);
	close(mCtlPipe[1]);
}

shared_ptr<RelaySession> MediaRelayServer::createSession(const std::string &frontId, const std::pair<std::string,std::string> &frontRelayIps) {
	shared_ptr<RelaySession> s = make_shared<RelaySession>(this,frontId,frontRelayIps);
	mMutex.lock();
	mSessions.push_back(s);
	mMutex.unlock();
	if (!mRunning)
		start();

	LOGD("There are now %zu relay sessions running.", mSessions.size());
	/*write to the control pipe to wakeup the server thread */
	update();
	return s;
}

void MediaRelayServer::update() {
	/*write to the control pipe to wakeup the server thread */
	if (write(mCtlPipe[1], "e", 1) == -1)
		LOGE("MediaRelayServer: fail to write to control pipe.");
}

static void set_high_prio(){
	struct sched_param param;
	int policy=SCHED_RR;
	int result=0;
	int max_prio;
		
	memset(&param,0,sizeof(param));
		
	max_prio = sched_get_priority_max(policy);
	param.sched_priority=max_prio;
	if((result=pthread_setschedparam(pthread_self(),policy, &param))) {
		if (result==EPERM){
			/*
				The linux kernel has 
				sched_get_priority_max(SCHED_OTHER)=sched_get_priority_max(SCHED_OTHER)=0.
				As long as we can't use SCHED_RR or SCHED_FIFO, the only way to increase priority of a calling thread
				is to use setpriority().
			*/
			if (setpriority(PRIO_PROCESS,0,-20)==-1){
				LOGD("MediaRelayServer setpriority() failed: %s, nevermind.",strerror(errno));
			}else{
				LOGD("MediaRelayServer priority increased to maximum.");
			}
		}else LOGW("MediaRelayServer: pthread_setschedparam failed: %s",strerror(result));
	} else {
		LOGD("MediaRelayServer: priority set to [%s] and value [%i]",
				policy==SCHED_FIFO ? "SCHED_FIFO" : "SCHED_RR", param.sched_priority);
	}
}

void MediaRelayServer::run() {
	PollFd pfd(512);
	int ctl_index;
	int err;

	set_high_prio();
	while (mRunning) {
		pfd.reset();
		//fill the pollfd table
		mMutex.lock();
		for (auto it = mSessions.begin(); it != mSessions.end(); ++it) {
			if ((*it)->isUsed()) (*it)->fillPollFd(&pfd);
		}
		mMutex.unlock();

		ctl_index=pfd.addFd(mCtlPipe[0],POLLIN);
		
		err = poll(pfd.getPfd(), pfd.getCurIndex(), 1000);
		if (err > 0) {
			//examine pollfd results
			if (pfd.getREvents(ctl_index) & POLLIN) {
				char tmp;
				if (read(mCtlPipe[0], &tmp, 1) == -1) {
					LOGE("Fail to read from control pipe.");
				}
			}
			time_t curtime = getCurrentTime();
			mMutex.lock();
			for (auto it = mSessions.begin(); it != mSessions.end();) {
				if (!(*it)->isUsed()) {
					it = mSessions.erase(it);
					LOGD("There are now %i relay sessions running.", (int) mSessions.size());
				} else {
					(*it)->checkPollFd(&pfd,curtime);
					++it;
				}
			}
			mMutex.unlock();
		}
	}
}

void *MediaRelayServer::threadFunc(void *arg) {
	MediaRelayServer *zis = (MediaRelayServer*) arg;
	zis->run();
	return NULL;
}
