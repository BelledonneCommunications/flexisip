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

#include "stun.hh"
#include "common.hh"

#include <arpa/inet.h>
#include <poll.h>

StunServer::StunServer(int port){
	mPort=port;
	mSock=-1;
}

int StunServer::start(){
	int err;
	struct sockaddr_in laddr;

	mSock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if (mSock==-1){
		LOGE("Could not create socket: %s",strerror(errno));
		return -1;
	}

	laddr.sin_family=AF_INET;
	laddr.sin_addr.s_addr=INADDR_ANY;
	laddr.sin_port=htons(mPort);
	
	err=bind(mSock,(struct sockaddr*)&laddr,sizeof(laddr));
	if (err==-1){
		LOGE("Could not bind STUN server to port %i", mPort);
		return -1;
	}
	
	mRunning=true;
	pthread_create(&mThread,NULL,&StunServer::threadfunc,this);
	return 0;
}

void StunServer::stop(){
	mRunning=false;
	pthread_join(mThread,NULL);
}

void StunServer::run(){
	while(mRunning){
		struct pollfd pfd[1];
		uint8_t buf[500];
		int err;
		
		pfd[0].fd=mSock;
		pfd[0].events=POLLIN;
		pfd[0].revents=0;
		
		err=poll(pfd,1,40);
		if (err>0 && (pfd[0].revents & POLLIN)){
			struct sockaddr_storage ss;
			socklen_t slen=sizeof(ss);
			err=recvfrom(mSock,buf,sizeof(buf),0,(struct sockaddr*) &ss,&slen);
			if (err>0){
				StunAddress4 from,myaddr,altaddr,dest;
				StunMessage resp;
				StunAtrString passwd;
				struct sockaddr_in *fromaddr=(struct sockaddr_in*)&ss;
				struct sockaddr_in srcaddr;
				socklen_t srcaddrlen=sizeof(srcaddr);
				
				bool_t changePort=FALSE;
				bool_t changeIP=FALSE;

				memset(&from,0,sizeof(from));
				memset(&myaddr,0,sizeof(myaddr));
				memset(&altaddr,0,sizeof(altaddr));
				memset(&dest,0,sizeof(dest));
				memset(&resp,0,sizeof(resp));
				memset(&passwd,0,sizeof(passwd));

				from.port=ntohs(fromaddr->sin_port);
				from.addr=ntohl(fromaddr->sin_addr.s_addr);
				
				if (getsockname(mSock,(struct sockaddr*)&srcaddr,&srcaddrlen)==-1){
					LOGE("getsockname() error: %s",strerror(errno));
					continue;
				}
				myaddr.port=ntohs(srcaddr.sin_port);
				myaddr.addr=ntohl(srcaddr.sin_addr.s_addr);
				
				bool_t ret=stunServerProcessMsg((char*)buf,err,&from,&myaddr,&altaddr,&resp,&dest,&passwd,&changeIP,&changePort);
				if (!ret){
					LOGW("Fail to parse stun request.");
					continue;
				}
				if (changeIP==FALSE && changePort==FALSE){
					unsigned int bytes=stunEncodeMessage(&resp,(char*)buf,sizeof(buf),&passwd);
					if (bytes>0){
						struct sockaddr_in destaddr;
						char tmp[32];
						destaddr.sin_family=AF_INET;
						destaddr.sin_port=htons(dest.port);
						destaddr.sin_addr.s_addr=htonl(dest.addr);
						err=sendto(mSock,buf,bytes,0,(struct sockaddr*)&destaddr,sizeof(destaddr));
						if (err==-1){
							LOGW("Fail to send stun response to %s:%i",
								 inet_ntop(AF_INET,&destaddr,tmp,sizeof(tmp)),dest.addr);
						}
					}else LOGE("stunEncodeMessage() failed.");
				}else LOGW("Received stun request with changeIP or changePort, not supported yet");
			}
		}
	}
}

void * StunServer::threadfunc(void *arg){
	StunServer *zis=(StunServer*)arg;
	zis->run();
	return NULL;
}

StunServer::~StunServer(){
	if (mRunning) stop();
}
