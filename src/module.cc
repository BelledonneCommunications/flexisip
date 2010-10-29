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

#include <algorithm>
using namespace::std;

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
		m->setName(i->getModuleName());
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

Module::Module(Agent *ag ) : mAgent(ag), mEnabled(true){
}

Module::~Module(){
}

Agent *Module::getAgent()const{
	return mAgent;
}

nta_agent_t *Module::getSofiaAgent()const{
	return mAgent->getSofiaAgent();
}

void Module::enable(bool enabled){
	mEnabled=enabled;
}

bool Module::isEnabled()const{
	return mEnabled;
}

const std::string &Module::getModuleName(){
	return mName;
}

void Module::setName(const std::string &name){
	mName=name;
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

void ModuleToolbox::addRecordRoute(su_home_t *home, Agent *ag, sip_t *sip){
	sip_record_route_t *rr=sip_record_route_format(home,"<sip:%s:%i;lr>",ag->getLocAddr().c_str(),ag->getPort());
	if (sip->sip_record_route==NULL){
		sip->sip_record_route=rr;
	}else{
		sip_record_route_t *it,*last_it=NULL;	
		for(it=sip->sip_record_route;it!=NULL;it=it->r_next){
			/*make sure we are not already in*/
			if (strcmp(it->r_url->url_host,ag->getLocAddr().c_str())==0 
			    && sipPortToInt(it->r_url->url_port)==ag->getPort())
				return;
			last_it=it;
		}
		last_it->r_next=rr;
	}
}
