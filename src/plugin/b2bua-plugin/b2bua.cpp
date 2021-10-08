/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/agent.hh>
#include <flexisip/plugin.hh>
#include <flexisip/logmanager.hh>
#include <flexisip/module.hh>
#include "flexisip/utils/sip-uri.hh"

using namespace flexisip;
using namespace std;

namespace {
	constexpr int B2buaPluginVersion = 1;
	constexpr char B2buaPluginName[] = "Back2Back User Agent plugin";
}

// =============================================================================
// Plugin.
// =============================================================================

class B2bua;

class B2bua : public Module, ModuleToolbox {
public:
	B2bua(Agent *agent) : Module(agent) {
		su_home_init(&mHome);
	}
	~B2bua() {
		su_home_deinit(&mHome);
	}

private:
	unique_ptr<SipUri> mDestRoute;
	su_home_t mHome;
	bool isValidNextConfig(const ConfigValue &cv) override;
	void onDeclare(GenericStruct *moduleConfig) override;
	void onLoad(const GenericStruct *moduleConfig) override;
	void onUnload() override;

	void onRequest(shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(shared_ptr<ResponseSipEvent> &ev) override;
};

namespace {
	ModuleInfo<B2bua> B2buaInfo(
		"B2bua",
		"This module deploys a configurable back-to-back User Agent.  TODO: - list agent capacities",
		{ "Authentication" },
		ModuleInfoBase::ModuleOid::Plugin
	);
}

FLEXISIP_DECLARE_PLUGIN(B2buaInfo, B2buaPluginName, B2buaPluginVersion);

// -----------------------------------------------------------------------------

void B2bua::onDeclare(GenericStruct *moduleConfig) {
	ConfigItemDescriptor configs[] = {
		{String, "b2bua-server", "A sip uri where to send all the relevent requests.", "sip:127.0.0.1:6067;transport=tcp"},
		config_item_end};
	moduleConfig->get<ConfigBoolean>("enabled")->setDefault("false");
	moduleConfig->addChildrenValues(configs);
}

bool B2bua::isValidNextConfig(const ConfigValue &cv) {
	GenericStruct *module_config = dynamic_cast<GenericStruct *>(cv.getParent());
	if (!module_config->get<ConfigBoolean>("enabled")->readNext())
		return true;
	if (cv.getName() == "b2bua-server") {
		url_t *uri = url_make(&mHome, cv.getName().c_str());
		if (!uri) {
			SLOGE << getModuleName() << ": wrong destination uri for back to back user agent server [" << cv.getName() << "]";
			return false;
		} else {
			su_free(&mHome, uri);
		}
	}
	return true;
}


void B2bua::onLoad(const GenericStruct *moduleConfig) {
	string destRouteStr = moduleConfig->get<ConfigString>("b2bua-server")->read();
	try {
		mDestRoute.reset(new SipUri(destRouteStr));
	} catch (const invalid_argument &e) {
		LOGF("Invalid SIP URI (%s) in 'b2bua-server' parameter of 'B2bua' module: %s", destRouteStr.c_str(), e.what());
	}
	SLOGI << getModuleName() << ": b2bua server is [" << mDestRoute->str() << "]";
}

void B2bua::onUnload() {
}

void B2bua::onRequest(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();
	SLOGD<<"B2bua onRequest, request method is "<<sip_method_name(sip->sip_request->rq_method, "UNKNOWN METHOD");
	if (sip->sip_request->rq_method == sip_method_invite) {
		// Do we have the "flexisip-b2bua" custom header? If no, we must intercept the call. TODO: have more control on intercepted call using configuration
		sip_unknown_t *header = ModuleToolbox::getCustomHeaderByName(sip, "flexisip-b2bua");
		if (header == NULL) {
			cleanAndPrependRoute(
				this->getAgent(),
				ev->getMsgSip()->getMsg(),
				ev->getSip(),
				sip_route_create(&mHome, mDestRoute->get(), nullptr)
			);
			SLOGD<<"B2bua onRequest, clean and prepend done to route "<<mDestRoute->str();
		} else { // Do not intercept the call
			//TODO: Remove the custom header flexisip-b2bua
			SLOGD<<"B2bua onRequest, ignore INVITE with custom header set to "<<std::string(header->un_value);
		}
	}
}

void B2bua::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	SLOGD<<"B2bua onResponse";
}
