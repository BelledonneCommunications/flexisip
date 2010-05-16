#include "agent.hh"

#include <algorithm>
#include <functional>

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

bool Transaction::matches(sip_t *sip){
	sip_from_t *from=sip->sip_from;
	sip_from_t *to=sip->sip_to;
	sip_cseq_t *cseq=sip->sip_cseq;
	return 
		from_match(mFrom,from) && from_match(mTo,to) 
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

int Agent::onRequest(msg_t *msg, sip_t *sip){
	sip_via_t *via;
	su_home_t home;

	su_home_init(&home);
	switch(sip->sip_request->rq_method){
		case sip_method_invite:
			LOGD("This is an invite");
			break;
	}
	//add on top of vias and forwards to destination
	via=nta_agent_via(mAgent);
	nta_msg_tsend (mAgent,msg,URL_STRING_MAKE(sip->sip_request->rq_url),SIPTAG_VIA(via),SIPTAG_END());
	
	su_home_deinit(&home);
}

int Agent::onResponse(msg_t *msg, sip_t *sip){
	sip_via_t*	via;
	su_home_t home;
	url_t *url;
	
	su_home_init(&home);

	/*remove top via and forwards to it*/
	via=sip_via_remove (msg,sip);
	url=url_format(&home,"sip:%s:%i",via->v_received ? via->v_received : via->v_host,
	               via->v_rport ? via->v_rport : via->v_port);
	nta_msg_tsend(mAgent,msg,(url_string_t*)url,SIPTAG_END());

	su_home_deinit(&home);
}

int Agent::onIncomingMessage(msg_t *msg, sip_t *sip){
	LOGD("Receiving new SIP message: %s",(const char*)sip->sip_common[0].h_data);
	if (sip->sip_request)
		return onRequest(msg,sip);
	else{
		return onResponse(msg,sip);
	}
}

Transaction * Agent::createTransaction(sip_t *request){
	Transaction *t=new Transaction(request);
	mTransactions.push_back(t);
	return t;
}

Transaction *Agent::findTransaction(sip_t *sip){
	list<Transaction*>::iterator it;
	it=find_if(mTransactions.begin(), mTransactions.end(), bind2nd(mem_fun(&Transaction::matches),sip));
	if (it==mTransactions.end())
		return NULL;
	return *it;
}

void Agent::deleteTransaction (Transaction *t){
	mTransactions.remove(t);
	delete t;
}

int Agent::messageCallback(nta_agent_magic_t *context, nta_agent_t *agent,msg_t *msg,sip_t *sip){
	Agent *a=(Agent*)context;
	return a->onIncomingMessage(msg,sip);
}

