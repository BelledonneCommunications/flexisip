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
