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


#include "agent.hh"

#include "etchosts.hh"

using namespace::std;

Transaction::Transaction(sip_t *request){
	su_home_init(&mHome);
	mFrom=sip_from_dup(&mHome,request->sip_from);
	mTo=sip_from_dup(&mHome,request->sip_to);
	mCseq=sip_cseq_dup(&mHome,request->sip_cseq);
	mUser=NULL;
}

Transaction::~Transaction(){
	su_home_deinit (&mHome);
}

void Transaction::setUserPointer(void *up){
	mUser=up;
}

void *Transaction::getUserPointer()const{
	return mUser;
}

static bool from_match(sip_from_t *f1, sip_from_t *f2){
	char a1[128];
	char a2[128];
	sip_from_e(a1,sizeof(a1)-1,(msg_header_t*)f1,0);
	sip_from_e(a2,sizeof(a2)-1,(msg_header_t*)f2,0);
	LOGD("Comparing %s and %s",a1,a2);
	return sip_addr_match(f1,f2)==0;
}

static bool to_match(sip_to_t *f1, sip_to_t *f2){
	char a1[128];
	char a2[128];
	sip_to_e(a1,sizeof(a1)-1,(msg_header_t*)f1,0);
	sip_to_e(a2,sizeof(a2)-1,(msg_header_t*)f2,0);
	LOGD("Comparing %s and %s",a1,a2);
	return sip_addr_match(f1,f2)==0;
}

bool Transaction::matches(sip_t *sip){
	sip_from_t *from=sip->sip_from;
	sip_from_t *to=sip->sip_to;
	sip_cseq_t *cseq=sip->sip_cseq;
	return 
		from_match(mFrom,from) && to_match(mTo,to) 
		&& mCseq->cs_seq==cseq->cs_seq && mCseq->cs_method==cseq->cs_method;
}


Agent::Agent(su_root_t* root, const char *locaddr, int port) : mLocAddr(locaddr), mPort(port){
	char sipuri[128]={0};
	snprintf(sipuri,sizeof(sipuri)-1,"sip:%s:%i;transport=UDP",locaddr,port);
	mAgent=nta_agent_create(root,
		(url_string_t*)sipuri,
			&Agent::messageCallback,
			(nta_agent_magic_t*)this,
			NULL,NULL);
	if (mAgent==NULL){
		LOGE("Could not create sofia mta.");
	}
	EtcHostsResolver::get();
}

Agent::~Agent(){
	if (mAgent)
		nta_agent_destroy(mAgent);
}

void Agent::loadConfig(ConfigManager *cm){
	mAliases=cm->getArea("global").get("aliases",list<string>());
	LOGD("List of host aliases:");
	for(list<string>::iterator it=mAliases.begin();it!=mAliases.end();++it){
		LOGD("%s",(*it).c_str());
	}
}

void Agent::setDomain(const std::string &domain){
	mDomain=domain;
}

bool Agent::isUs(const url_t *url)const{
	int port=(url->url_port!=NULL) ? atoi(url->url_port) : 5060;
	if (port!=mPort) return false;
	if (strcmp(url->url_host,mLocAddr.c_str())==0) return true;
	list<string>::const_iterator it;
	for(it=mAliases.begin();it!=mAliases.end();++it){
		if (strcasecmp(url->url_host,(*it).c_str())==0) return true;
	}
	return false;
}

void Agent::addRecordRoute(su_home_t *home, msg_t *msg, sip_t *sip){
	sip_record_route_t *rr=sip_record_route_format(home,"<sip:%s:%i;lr>",mLocAddr.c_str(),mPort);
	if (sip->sip_record_route==NULL){
		sip->sip_record_route=rr;
	}else{
		sip_record_route_t *it;
		for(it=sip->sip_record_route;it->r_next!=NULL;it=it->r_next){
		}
		it->r_next=rr;
	}
}

int Agent::forwardRequest(msg_t *msg, sip_t *sip){
	su_home_t home;
	size_t msg_size;
	char *buf;
	const char *domain;
	url_t* dest=NULL;

	dest=sip->sip_request->rq_url;
	su_home_init(&home);
	switch(sip->sip_request->rq_method){
		case sip_method_invite:
			LOGD("This is an invite");
			break;
		case sip_method_register:
			LOGD("This is a register");
			domain=sip->sip_to->a_url->url_host;
			if (strcasecmp(domain,mDomain.c_str())!=0){
				LOGD("This domain (%s) is not managed by us, forwarding.",domain);
				//rewrite the request uri to the domain
				//this assume the domain is also the proxy
				sip->sip_request->rq_url->url_host=sip->sip_to->a_url->url_host;
				sip->sip_request->rq_url->url_port=sip->sip_to->a_url->url_port;
			}
		case sip_method_ack:
		default:
			break;
	}
	// removes top route header if it maches us
	if (sip->sip_route!=NULL){
		if (isUs(sip->sip_route->r_url)){
			sip_route_remove(msg,sip);
		}
		if (sip->sip_route!=NULL){
			/*forward to this route*/
			dest=sip->sip_route->r_url;
		}
	}
	std::string ip;
	if (EtcHostsResolver::get()->resolve(dest->url_host,&ip)){
		LOGD("Found %s in /etc/hosts",dest->url_host);
		dest->url_host=ip.c_str();
	}
	buf=msg_as_string(&home, msg, NULL, 0,&msg_size);
	LOGD("About to forward request to %s:\n%s",url_as_string(&home,dest),buf);
	nta_msg_tsend (mAgent,msg,(url_string_t*)dest,TAG_END());
	su_home_deinit(&home);
	return 0;
}

int Agent::forwardResponse(msg_t *msg, sip_t *sip){
	su_home_t home;
	char *buf;
	size_t msg_size;
	
	su_home_init(&home);

	buf=msg_as_string(&home, msg, NULL, 0,&msg_size);
	LOGD("About to forward response:\n%s",buf);
	
	nta_msg_tsend(mAgent,msg,(url_string_t*)NULL,TAG_END());

	su_home_deinit(&home);
	return 0;
}

int Agent::onRequest(msg_t *msg, sip_t *sip){
	return forwardRequest (msg,sip);
}

int Agent::onResponse(msg_t *msg, sip_t *sip){
	return forwardResponse (msg,sip);
}

int Agent::onIncomingMessage(msg_t *msg, sip_t *sip){
	su_home_t home;
	size_t msg_size;
	char *buf;
	int err;
	su_home_init(&home);
	buf=msg_as_string(&home, msg, NULL, 0,&msg_size);
	LOGD("Receiving new SIP message:\n%s",buf);
	if (sip->sip_request)
		err=onRequest(msg,sip);
	else{
		err=onResponse(msg,sip);
	}
	su_home_deinit(&home);
	return err;
}

int Agent::messageCallback(nta_agent_magic_t *context, nta_agent_t *agent,msg_t *msg,sip_t *sip){
	Agent *a=(Agent*)context;
	return a->onIncomingMessage(msg,sip);
}

void Agent::idle(){
}
