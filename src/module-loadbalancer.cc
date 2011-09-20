/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2011  Belledonne Communications SARL.

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


class LoadBalancer : public Module{
	public:
		LoadBalancer(Agent *ag);
		virtual ~LoadBalancer();
		virtual void onDeclare(ConfigStruct *module_config);
		virtual void onLoad(Agent *ag, const ConfigStruct * modconf);
		virtual void onRequest(SipEvent *ev);
		virtual void onResponse(SipEvent *ev);
	private:
		static ModuleInfo<LoadBalancer> sInfo;
};

ModuleInfo<LoadBalancer> LoadBalancer::sInfo("LoadBalancer",
                                             "This module performs load balancing between a set of configured destination proxies.");

LoadBalancer::LoadBalancer(Agent *ag) : Module(ag){
}

LoadBalancer::~LoadBalancer(){
}

void LoadBalancer::onDeclare(ConfigStruct *module_config){
	/*we need to be disabled by default*/
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
}

void LoadBalancer::onLoad(Agent *ag, const ConfigStruct * modconf){
}

void LoadBalancer::onRequest(SipEvent *ev){
}

void LoadBalancer::onResponse(SipEvent *ev){
}
