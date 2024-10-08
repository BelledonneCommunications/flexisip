/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include "flexisip/utils/sip-uri.hh"

#include "agent.hh"
#include "b2bua/b2bua-server.hh"
#include "module-toolbox.hh"

using namespace std;

// =============================================================================
// Module declaration
// =============================================================================
namespace flexisip {

class B2bua : public Module {
	friend std::shared_ptr<Module> ModuleInfo<B2bua>::create(Agent*);

public:
	~B2bua() {
		su_home_deinit(&mHome);
	}

private:
	B2bua(Agent* agent, const ModuleInfoBase* moduleInfo) : Module(agent, moduleInfo) {
		su_home_init(&mHome);
	}

	bool isValidNextConfig(const ConfigValue& cv) override;
	void onLoad(const GenericStruct* moduleConfig) override;
	void onUnload() override;

	void onRequest(shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(shared_ptr<ResponseSipEvent>& ev) override;

	static ModuleInfo<B2bua> sInfo;
	unique_ptr<SipUri> mDestRoute;
	su_home_t mHome;
	string mB2buaUserAgent;
};

ModuleInfo<B2bua> B2bua::sInfo{
    "B2bua",
    "This module is in charge of intercepting calls and route them to the back-to-back user agent server",
    {"Authentication", "ExternalAuthentication", "Authorization"},
    ModuleInfoBase::ModuleOid::B2bua,
    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor configs[] = {
	        {
	            String,
	            "b2bua-server",
	            "A sip uri where to send all the relevant requests.",
	            "sip:127.0.0.1:6067;transport=tcp",
	        },
	        config_item_end,
	    };
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    moduleConfig.addChildrenValues(configs);
    },
};

// -----------------------------------------------------------------------------
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
	const auto* b2buaDestinationRouteParameter = moduleConfig->get<ConfigString>("b2bua-server");
	const auto destRouteStr = b2buaDestinationRouteParameter->read();
	try {
		mDestRoute = make_unique<SipUri>(destRouteStr);
	} catch (const sofiasip::InvalidUrlError& e) {
		throw FlexisipException{"Invalid SIP URI " + destRouteStr + " in parameter " +
		                        b2buaDestinationRouteParameter->getCompleteName() + ": " + e.what()};
	}
	SLOGI << "module::" << getModuleName() << ": b2bua server is [" << mDestRoute->str() << "]";

	const auto* b2buaServerConfig = getAgent()->getConfigManager().getRoot()->get<GenericStruct>("b2bua-server");
	const auto userAgent = b2bua::parseUserAgentFromConfig(b2buaServerConfig->get<ConfigString>("user-agent")->read());
	mB2buaUserAgent = userAgent.first + (userAgent.second.empty() ? "" : ("/" + userAgent.second));
	SLOGI << "module::" << getModuleName() << ": ignore INVITE and CANCEL requests with \"User-Agent\" header set to "
	      << mB2buaUserAgent;
}

void B2bua::onUnload() {
}

void B2bua::onRequest(shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getSip();
	if (sip->sip_request->rq_method == sip_method_invite || sip->sip_request->rq_method == sip_method_cancel) {
		// Is the request coming from the B2BUA? If no, we must intercept it.
		const auto requestIsFromB2BUA = sip->sip_user_agent and sip->sip_user_agent->g_string == mB2buaUserAgent;

		if (!requestIsFromB2BUA) {
			ModuleToolbox::cleanAndPrependRoute(this->getAgent(), ev->getMsgSip()->getMsg(), ev->getSip(),
			                                    sip_route_create(&mHome, mDestRoute->get(), nullptr));
			SLOGD << "Clean and prepend done to route " << mDestRoute->str();
		} else { // Do not intercept the call
			SLOGD << "Ignore INVITE with \"User-Agent\" header set to " << mB2buaUserAgent;
		}
	}
}

void B2bua::onResponse([[maybe_unused]] shared_ptr<ResponseSipEvent>& ev) {
}

} // namespace flexisip