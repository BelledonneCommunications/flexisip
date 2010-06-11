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
}

Agent::~Agent(){
	if (mAgent)
		nta_agent_destroy(mAgent);
}

void Agent::setDomain(const std::string &domain){
	mDomain=domain;
}

int Agent::onRequest(msg_t *msg, sip_t *sip){
	su_home_t home;
	size_t msg_size;
	char *buf;
	const char *domain;
	url_string_t* dest=NULL;

	dest=(url_string_t*)sip->sip_request->rq_url;
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
			break;
		case sip_method_ack:
			// sofia does not remove the route for acks, so do it
			if (sip->sip_route!=NULL)
				sip_route_remove(msg,sip);
			break;
		default:
			break;
	}
	buf=msg_as_string(&home, msg, NULL, 0,&msg_size);
	LOGD("About to forward request:\n%s",buf);
	nta_msg_tsend (mAgent,msg,dest,TAG_END());
	su_home_deinit(&home);
	return 0;
}

int Agent::onResponse(msg_t *msg, sip_t *sip){
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

