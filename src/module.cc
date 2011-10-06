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
#include "entryfilter.hh"

#include <algorithm>
using namespace::std;

Module *ModuleInfoBase::create(Agent *ag){
	Module *mod=_create(ag);
	mod->setInfo(this);
	return mod;
}

ModuleFactory * ModuleFactory::sInstance=NULL;

ModuleFactory *ModuleFactory::get(){
	if (sInstance==NULL){
		sInstance=new ModuleFactory();
	}
	return sInstance;
}

struct hasName{
	hasName(const std::string &ref) : match(ref){
	}
	bool operator()(ModuleInfoBase *info){
		return info->getModuleName()==match;
	}
	const std::string &match;
};

Module *ModuleFactory::createModuleInstance(Agent *ag, const std::string &modname){
	list<ModuleInfoBase*>::iterator it;
	it=find_if(mModules.begin(), mModules.end(), hasName(modname));
	if (it!=mModules.end()){
		Module *m;
		ModuleInfoBase *i=*it;
		m=i->create(ag);
		LOGI("Creating module instance for [%s]",m->getModuleName().c_str());
		return m;
	}
	LOGE("Could not find any registered module with name %s",modname.c_str());
	return NULL;
}

void ModuleFactory::registerModule(ModuleInfoBase *m){
	LOGI("Registering module %s",m->getModuleName().c_str());
	mModules.push_back(m);
}

Module::Module(Agent *ag ) : mAgent(ag){
	mFilter=new ConfigEntryFilter();
}

Module::~Module(){
}

void Module::setInfo(ModuleInfoBase *i){
	mInfo=i;
}

Agent *Module::getAgent()const{
	return mAgent;
}

nta_agent_t *Module::getSofiaAgent()const{
	return mAgent->getSofiaAgent();
}

void Module::declare(ConfigStruct *root){
	mModuleConfig=new ConfigStruct("module::"+getModuleName(),mInfo->getModuleHelp());
	root->addChild(mModuleConfig);
	mFilter->declareConfig(mModuleConfig);
	onDeclare(mModuleConfig);
}

void Module::load(Agent *agent){
	mFilter->loadConfig(mModuleConfig);
	if (mFilter->isEnabled()) onLoad(agent,mModuleConfig);
}

void Module::processRequest(SipEvent *ev){
	if (mFilter->canEnter(ev->mSip)){
		LOGD("Invoking onRequest() on module %s",getModuleName().c_str());
		onRequest(ev);
	}
}

void Module::processResponse(SipEvent *ev){
	if (mFilter->canEnter(ev->mSip)){
		LOGD("Invoking onResponse() on module %s",getModuleName().c_str());
		onResponse(ev);
	}
}

void Module::idle(){
	onIdle();
}

const std::string &Module::getModuleName(){
	return mInfo->getModuleName();
}


bool ModuleToolbox::sipPortEquals(const char *p1, const char *p2){
	int n1,n2;
	n1=n2=5060;
	if (p1 && p1[0]!='\0')
		n1=atoi(p1);
	if (p2 && p2[0]!='\0')
		n2=atoi(p2);
	return n1==n2;
}

int ModuleToolbox::sipPortToInt(const char *port){
	if (port==NULL || port[0]=='\0') return 5060;
	else return atoi(port);
}

void ModuleToolbox::prependRoute(su_home_t *home, Agent *ag, msg_t *msg, sip_t *sip, const char *route){
	// removes top route headers if they maches us
	sip_route_t *r;
	r=sip_route_format(home,"%s",route);
	while (sip->sip_route!=NULL && ag->isUs(sip->sip_route->r_url) ){
		sip_route_remove(msg,sip);
	}
	r->r_next=sip->sip_route;
	msg_header_remove_all(msg,(msg_pub_t*)sip,(msg_header_t*)sip->sip_route);
	msg_header_insert(msg,(msg_pub_t*)sip,(msg_header_t*)r);
	sip->sip_route=r;
}

void ModuleToolbox::addRecordRoute(su_home_t *home, Agent *ag, msg_t *msg, sip_t *sip, const char *transport){
	sip_via_t *via=sip->sip_via;
	sip_record_route_t *rr;
	bool transport_given=(transport!=NULL);

	if (transport==NULL) transport=sip_via_transport(via);

	if (strcasecmp(transport,"UDP")!=0){
		if (ag->getPort()!=5060){
			rr=sip_record_route_format(home,"<sip:%s:%i;lr;transport=%s>",ag->getPublicIp().c_str(),ag->getPort(),transport);
		}else{
			rr=sip_record_route_format(home,"<sip:%s;lr;transport=%s>",ag->getPublicIp().c_str(),transport);
		}
	}else {
		if (ag->getPort()!=5060){
			rr=sip_record_route_format(home,"<sip:%s:%i;lr>",ag->getPublicIp().c_str(),ag->getPort());
		}else{
			rr=sip_record_route_format(home,"<sip:%s;lr>",ag->getPublicIp().c_str());
		}
	}
	if (sip->sip_record_route==NULL){
		sip->sip_record_route=rr;
	}else{
		/*make sure we are not already in*/
		if (!transport_given && sip->sip_record_route && ag->isUs(sip->sip_record_route->r_url,false))
			return;
		rr->r_next=sip->sip_record_route;
		msg_header_remove_all(msg,(msg_pub_t*)sip,(msg_header_t*)sip->sip_record_route);
		msg_header_insert(msg,(msg_pub_t*)sip,(msg_header_t*)rr);
		sip->sip_record_route=rr;
	}
}

bool ModuleToolbox::fromMatch(const sip_from_t *from1, const sip_from_t *from2){
	if (url_cmp(from1->a_url,from2->a_url)==0){
		if (from1->a_tag && from2->a_tag && strcmp(from1->a_tag,from2->a_tag)==0)
			return true;
		if (from1->a_tag==NULL && from2->a_tag==NULL) return true;
	}
	return false;
}

bool ModuleToolbox::matchesOneOf(const char *item, const std::list<std::string> &set){
	list<string>::const_iterator it;
	for(it=set.begin();it!=set.end();++it){
		const char *tmp=(*it).c_str();
		if (tmp[0]=='*'){
			/*the wildcard matches everything*/
			return true;
		}else{
			if (strcmp(item,tmp)==0)
				return true;
		}
	}
	return false;
}

bool ModuleToolbox::fixAuthChallengeForSDP(su_home_t *home, msg_t *msg, sip_t *sip){
	sip_auth_t *auth;
	msg_param_t *par;
	auth=sip->sip_www_authenticate;
	if (auth==NULL) auth=sip->sip_proxy_authenticate;
	if (auth==NULL) return true;
	if (auth->au_params==NULL) return true;
	par=msg_params_find_slot((msg_param_t*)auth->au_params,"qop");
	if (par!=NULL){
		if (strstr(*par,"auth-int")){
			LOGD("Authentication header has qop with 'auth-int', replacing by 'auth'");
			//if the qop contains "auth-int", replace it by "auth" so that it allows to modify the SDP
			*par=su_strdup(home,"qop=\"auth\"");
		}
	}
	return true;
}

