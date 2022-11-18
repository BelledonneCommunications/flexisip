/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

using namespace std;
using namespace flexisip;

class LoadBalancer : public Module, public ModuleToolbox {
public:
	LoadBalancer(Agent *ag);
	virtual ~LoadBalancer();
	virtual void onDeclare(GenericStruct *module_config);
	virtual void onLoad(const GenericStruct *modconf);
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

private:
	vector<string> mRoutes;
	int mRoutesCount;

	static ModuleInfo<LoadBalancer> sInfo;
};

LoadBalancer::LoadBalancer(Agent *ag) : Module(ag) {
}

LoadBalancer::~LoadBalancer() {
}

void LoadBalancer::onDeclare(GenericStruct *module_config) {
	/*we need to be disabled by default*/
	module_config->get<ConfigBoolean>("enabled")->setDefault("false");
	ConfigItemDescriptor items[] = { { StringList,
		"routes",
		"Whitespace separated list of sip routes to balance the requests. Example: <sip:192.168.0.22> <sip:192.168.0.23>",
		"" }, config_item_end };
	module_config->addChildrenValues(items);
}

void LoadBalancer::onLoad(const GenericStruct *modconf) {
	list<string> routes = modconf->get<ConfigStringList>("routes")->read();
	list<string>::iterator it;

	LOGI("Load balancer configured to balance over:");
	for (it = routes.begin(); it != routes.end(); ++it) {
		mRoutes.push_back(*it);
		LOGI("%s", (*it).c_str());
	}
	mRoutesCount = mRoutes.size();
}

void LoadBalancer::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	uint32_t call_hash;
	sip_t *sip = ms->getSip();
	int index;

	if (mRoutesCount == 0)
		return;

	/* very simple load sharing algorithm, based on randomness of call id*/
	if (sip->sip_call_id) {
		const char *route;
		call_hash = sip->sip_call_id->i_hash;
		index = call_hash % mRoutesCount;
		route = mRoutes[index].c_str();
		cleanAndPrependRoute(getAgent(), ms->getMsg(), sip, sip_route_make(ms->getHome(), route));
	} else {
		LOGW("request has no call id");
	}
}

void LoadBalancer::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	/*nothing to do*/
}

ModuleInfo<LoadBalancer> LoadBalancer::sInfo(
	"LoadBalancer",
	"This module performs load balancing between a set of configured destination proxies.",
	{ "PushNotification" },
	ModuleInfoBase::ModuleOid::LoadBalancer,
	ModuleClass::Experimental
);
