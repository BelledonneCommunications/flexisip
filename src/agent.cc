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
#include <algorithm>
#include <sstream>

using namespace::std;

Agent::Agent(su_root_t* root, const char *locaddr, int port) : mLocAddr(locaddr), mPort(port){
	char sipuri[128]={0};
	// compute a network wide unique id
	std::ostringstream oss;
	oss << locaddr << "_" << port;
	mUniqueId = oss.str();

	snprintf(sipuri,sizeof(sipuri)-1,"sip:%s:%i;transport=UDP",locaddr,port);
	mAgent=nta_agent_create(root,
		(url_string_t*)sipuri,
			&Agent::messageCallback,
			(nta_agent_magic_t*)this,
			TAG_END());
	if (mAgent==NULL){
		LOGE("Could not create sofia mta.");
	}
	EtcHostsResolver::get();
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"NatHelper"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"Authentication"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"Registrar"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"ContactRouteInserter"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"MediaRelay"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"Transcoder"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"Forward"));

	mServerString="Flexisip/"VERSION " (sofia-sip-nta/" NTA_VERSION ")";

	for_each(mModules.begin(),mModules.end(),bind2nd(mem_fun(&Module::declare),
	                                                 ConfigManager::get()->getRoot()));
}

Agent::~Agent(){
	for_each(mModules.begin(),mModules.end(),delete_functor<Module>());
	if (mAgent)
		nta_agent_destroy(mAgent);
}

const char *Agent::getServerString()const{
	return mServerString.c_str();
}

void Agent::loadConfig(ConfigManager *cm){
	cm->loadStrict();//now that each module has declared its settings, we need to reload from the config file
	mAliases=cm->getGlobal()->get<ConfigStringList>("aliases")->read();
	LOGD("List of host aliases:");
	for(list<string>::iterator it=mAliases.begin();it!=mAliases.end();++it){
		LOGD("%s",(*it).c_str());
	}
	list<Module*>::iterator it;
	for(it=mModules.begin();it!=mModules.end();++it)
		(*it)->load(this);
}

void Agent::setDomain(const std::string &domain){
	mDomain=domain;
}

int Agent::countUsInVia(sip_via_t *via)const{
	int count = 0;
	for (sip_via_t *v = via;v!=NULL;v=v->v_next){
		if (isUs(v->v_host, v->v_port)) ++count;
	}

	return count;
}

bool Agent::isUs(const char *host, const char *port)const{
	int p=(port!=NULL) ? atoi(port) : 5060;
	if (p!=mPort) return false;
	if (strcmp(host,mLocAddr.c_str())==0) return true;
	list<string>::const_iterator it;
	for(it=mAliases.begin();it!=mAliases.end();++it){
		if (strcasecmp(host,(*it).c_str())==0) return true;
	}
	return false;
}

bool Agent::isUs(const url_t *url)const{
	return isUs(url->url_host, url->url_port);
}

void Agent::onRequest(msg_t *msg, sip_t *sip){
	list<Module*>::iterator it;
	SipEvent ev(msg,sip);
	for(it=mModules.begin();it!=mModules.end();++it){
		(*it)->processRequest(&ev);
		if (ev.finished()) break;
	}
}

void Agent::onResponse(msg_t *msg, sip_t *sip){
	list<Module*>::iterator it;
	SipEvent ev(msg,sip);
	for(it=mModules.begin();it!=mModules.end();++it){
		(*it)->processResponse(&ev);
		if (ev.finished()) break;
	}
}

int Agent::onIncomingMessage(msg_t *msg, sip_t *sip){
	su_home_t home;
	size_t msg_size;
	char *buf;

	su_home_init(&home);
	buf=msg_as_string(&home, msg, NULL, 0,&msg_size);
	LOGD("Receiving new SIP message:\n%s",buf);
	if (sip->sip_request)
		onRequest(msg,sip);
	else{
		onResponse(msg,sip);
	}
	su_home_deinit(&home);
	return 0;
}

int Agent::messageCallback(nta_agent_magic_t *context, nta_agent_t *agent,msg_t *msg,sip_t *sip){
	Agent *a=(Agent*)context;
	return a->onIncomingMessage(msg,sip);
}

void Agent::idle(){
	for_each(mModules.begin(),mModules.end(),mem_fun(&Module::idle));
}
const std::string& Agent::getUniqueId() const{
	return mUniqueId;
}
