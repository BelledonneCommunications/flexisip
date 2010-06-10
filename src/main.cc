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


#include "transcodeagent.hh"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

#define IPADDR_SIZE 32

static int get_local_ip_for_with_connect(int type, const char *dest, char *result){
	int err,tmp;
	struct addrinfo hints;
	struct addrinfo *res=NULL;
	struct sockaddr_storage addr;
	int sock;
	socklen_t s;

	memset(&hints,0,sizeof(hints));
	hints.ai_family=(type==AF_INET6) ? PF_INET6 : PF_INET;
	hints.ai_socktype=SOCK_DGRAM;
	/*hints.ai_flags=AI_NUMERICHOST|AI_CANONNAME;*/
	err=getaddrinfo(dest,"5060",&hints,&res);
	if (err!=0){
		LOGE("getaddrinfo() error: %s",gai_strerror(err));
		return -1;
	}
	if (res==NULL){
		LOGE("bug: getaddrinfo returned nothing.");
		return -1;
	}
	sock=socket(res->ai_family,SOCK_DGRAM,0);
	tmp=1;
	err=setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&tmp,sizeof(int));
	if (err<0){
		LOGW("Error in setsockopt: %s",strerror(errno));
	}
	err=connect(sock,res->ai_addr,res->ai_addrlen);
	if (err<0) {
		LOGE("Error in connect: %s",strerror(errno));
 		freeaddrinfo(res);
 		close(sock);
		return -1;
	}
	freeaddrinfo(res);
	res=NULL;
	s=sizeof(addr);
	err=getsockname(sock,(struct sockaddr*)&addr,&s);
	if (err!=0) {
		LOGE("Error in getsockname: %s",strerror(errno));
		close(sock);
		return -1;
	}
	
	err=getnameinfo((struct sockaddr *)&addr,s,result,IPADDR_SIZE,NULL,0,NI_NUMERICHOST);
	if (err!=0){
		LOGE("getnameinfo error: %s",strerror(errno));
	}
	close(sock);
	LOGI("Local interface to reach %s is %s.",dest,result);
	return 0;
}

static void usage(const char *arg0){
	printf("%s \t [--port <port number to listen>]\n"
	       "\t\t [--help]\n",arg0);
	exit(-1);
}

int main(int argc, char *argv[]){
	Agent *a;
	int port=5060;
	char localip[IPADDR_SIZE];
	const char *domain=NULL;
	int i;

	for(i=1;i<argc;++i){
		if (strcmp(argv[i],"--port")==0){
			i++;
			if (i<argc){
				port=atoi(argv[i]);
				continue;
			}
		}else if (strcmp(argv[i],"--domain")==0){
			i++;
			if (i<argc){
				domain=argv[i];
				continue;
			}
		}
		usage(argv[0]);
	}

	
	su_init();
	su_root_t *root=su_root_create(NULL);

	get_local_ip_for_with_connect (AF_INET,"87.98.157.38",localip);
	
	a=new TranscodeAgent(root,localip,port);
	if (domain) a->setDomain(domain);
	su_root_run(root);

	delete a;
    su_root_destroy(root);
	
}

