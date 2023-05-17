/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"
#include "flexisip/plugin.hh"
#include "flexisip/utils/sip-uri.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

using namespace std;

// =============================================================================
// Module declaration
// =============================================================================
namespace flexisip {

class B2bua : public Module, ModuleToolbox {
public:
	B2bua(Agent* agent) : Module(agent) {
		su_home_init(&mHome);
	}
	~B2bua() {
		su_home_deinit(&mHome);
	}

private:
	static ModuleInfo<B2bua> sInfo;
	unique_ptr<SipUri> mDestRoute;
	su_home_t mHome;
	bool isValidNextConfig(const ConfigValue& cv) override;
	void onDeclare(GenericStruct* moduleConfig) override;
	void onLoad(const GenericStruct* moduleConfig) override;
	void onUnload() override;

	void onRequest(shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(shared_ptr<ResponseSipEvent>& ev) override;
};

ModuleInfo<B2bua>
    B2bua::sInfo("B2bua",
                 "This module is in charge of intercepting calls and route them to the back-to-back user agent server",
                 {"Authentication", "ExternalAuthentication"},
                 ModuleInfoBase::ModuleOid::B2bua);

// -----------------------------------------------------------------------------

void B2bua::onDeclare(GenericStruct* moduleConfig) {
	ConfigItemDescriptor configs[] = {{String, "b2bua-server", "A sip uri where to send all the relevent requests.",
	                                   "sip:127.0.0.1:6067;transport=tcp"},
	                                  config_item_end};
	moduleConfig->get<ConfigBoolean>("enabled")->setDefault("false");
	moduleConfig->addChildrenValues(configs);
}

bool B2bua::isValidNextConfig(const ConfigValue& cv) {
	GenericStruct* module_config = dynamic_cast<GenericStruct*>(cv.getParent());
	if (!module_config->get<ConfigBoolean>("enabled")->readNext()) return true;
	if (cv.getName() == "b2bua-server") {
		url_t* uri = url_make(&mHome, cv.getName().c_str());
		if (!uri) {
			SLOGE << getModuleName() << ": wrong destination uri for back to back user agent server [" << cv.getName()
			      << "]";
			return false;
		} else {
			su_free(&mHome, uri);
		}
	}
	return true;
}

void B2bua::onLoad(const GenericStruct* moduleConfig) {
	string destRouteStr = moduleConfig->get<ConfigString>("b2bua-server")->read();
	try {
		mDestRoute.reset(new SipUri(destRouteStr));
	} catch (const invalid_argument& e) {
		LOGF("Invalid SIP URI (%s) in 'b2bua-server' parameter of 'B2bua' module: %s", destRouteStr.c_str(), e.what());
	}
	SLOGI << getModuleName() << ": b2bua server is [" << mDestRoute->str() << "]";
}

void B2bua::onUnload() {
}

void B2bua::onRequest(shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getSip();
	if (sip->sip_request->rq_method == sip_method_invite || sip->sip_request->rq_method == sip_method_cancel) {
		// Do we have the "flexisip-b2bua" custom header? If no, we must intercept the call.
		sip_unknown_t* header = ModuleToolbox::getCustomHeaderByName(sip, "flexisip-b2bua");

		if (header == NULL) {
			cleanAndPrependRoute(this->getAgent(), ev->getMsgSip()->getMsg(), ev->getSip(),
			                     sip_route_create(&mHome, mDestRoute->get(), nullptr));
			SLOGD << "B2bua onRequest, clean and prepend done to route " << mDestRoute->str();
		} else { // Do not intercept the call
			// TODO: Remove the custom header flexisip-b2bua
			SLOGD << "B2bua onRequest, ignore INVITE with custom header set to " << std::string(header->un_value);
		}
	}
}

void B2bua::onResponse([[maybe_unused]] shared_ptr<ResponseSipEvent>& ev) {
}

} // namespace flexisip
