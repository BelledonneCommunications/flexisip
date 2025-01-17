/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <vector>

#include <flexisip/module.hh>

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "module-toolbox.hh"

using namespace std;
using namespace flexisip;

class LoadBalancer : public Module {
	friend std::shared_ptr<Module> ModuleInfo<LoadBalancer>::create(Agent*);

public:
	~LoadBalancer() override;
	void onLoad(const GenericStruct* modconf) override;
	unique_ptr<RequestSipEvent> onRequest(unique_ptr<RequestSipEvent>&& ev) override;
	unique_ptr<ResponseSipEvent> onResponse(unique_ptr<ResponseSipEvent>&& ev) override;

private:
	LoadBalancer(Agent* ag, const ModuleInfoBase* moduleInfo);

	vector<string> mRoutes;
	int mRoutesCount;

	static ModuleInfo<LoadBalancer> sInfo;
};

LoadBalancer::LoadBalancer(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
}

LoadBalancer::~LoadBalancer() {
}

void LoadBalancer::onLoad(const GenericStruct* modconf) {
	list<string> routes = modconf->get<ConfigStringList>("routes")->read();
	list<string>::iterator it;

	SLOGI << "Load balancer configured to balance over:";
	for (it = routes.begin(); it != routes.end(); ++it) {
		mRoutes.push_back(*it);
		SLOGI << *it;
	}
	mRoutesCount = mRoutes.size();
}

unique_ptr<RequestSipEvent> LoadBalancer::onRequest(unique_ptr<RequestSipEvent>&& ev) {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	uint32_t call_hash;
	sip_t* sip = ms->getSip();
	int index;

	if (mRoutesCount == 0) return std::move(ev);

	/* very simple load sharing algorithm, based on randomness of call id*/
	if (sip->sip_call_id) {
		const char* route;
		call_hash = sip->sip_call_id->i_hash;
		index = call_hash % mRoutesCount;
		route = mRoutes[index].c_str();
		ModuleToolbox::cleanAndPrependRoute(getAgent(), ms->getMsg(), sip, sip_route_make(ms->getHome(), route));
	} else {
		SLOGW << "request has no call id";
	}
	return std::move(ev);
}

unique_ptr<ResponseSipEvent> LoadBalancer::onResponse(unique_ptr<ResponseSipEvent>&& ev) {
	/*nothing to do*/
	return std::move(ev);
}

ModuleInfo<LoadBalancer> LoadBalancer::sInfo(
    "LoadBalancer",
    "This module performs load balancing between a set of configured destination proxies.",
    {"PushNotification"},
    ModuleInfoBase::ModuleOid::LoadBalancer,

    [](GenericStruct& moduleConfig) {
	    /*we need to be disabled by default*/
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    ConfigItemDescriptor items[] = {
	        {
	            StringList,
	            "routes",
	            "Whitespace separated list of sip routes to balance the "
	            "requests. Example: <sip:192.168.0.22> <sip:192.168.0.23>",
	            "",
	        },
	        config_item_end,
	    };
	    moduleConfig.addChildrenValues(items);
    },
    ModuleClass::Experimental);