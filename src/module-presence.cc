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

#include <flexisip/logmanager.hh>
#include <flexisip/module.hh>
#include <flexisip/utils/sip-uri.hh>

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "exceptions/bad-configuration.hh"
#include "module-toolbox.hh"

using namespace std;
using namespace flexisip;

class ModulePresence : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ModulePresence>::create(Agent*);

private:
	static ModuleInfo<ModulePresence> sInfo;
	SipUri mDestRoute;
	su_home_t mHome;
	shared_ptr<SipBooleanExpression> mOnlyListSubscription;

	bool isValidNextConfig(const ConfigValue& cv) override {
		GenericStruct* module_config = dynamic_cast<GenericStruct*>(cv.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext()) return true;
		if (cv.getName() == "presence-server") {
			url_t* uri = url_make(&mHome, cv.getName().c_str());
			if (!uri) {
				LOGE << "Wrong destination URI for presence server [" << cv.getName() << "]";
				return false;
			} else {
				su_free(&mHome, uri);
			}
		}
		return true;
	}

	void onLoad(const GenericStruct* mc) override {
		auto presenceServerSetting = mc->get<ConfigString>("presence-server");
		auto destRouteStr = presenceServerSetting->read();
		if (destRouteStr.empty()) throw BadConfiguration{presenceServerSetting->getName() + " parameter must be set"};
		try {
			mDestRoute = SipUri(destRouteStr);
		} catch (const sofiasip::InvalidUrlError& e) {
			throw BadConfiguration{"invalid SIP URI ('" + destRouteStr + "') set in '" +
			                       presenceServerSetting->getCompleteName() + "'"};
		}

		mOnlyListSubscription = mc->get<ConfigBooleanExpression>("only-list-subscription")->read();
		LOGI << "Presence server is [" << mDestRoute.str() << "]";
		LOGI << "Non list subscription are " << (mOnlyListSubscription ? "not" : "")
		     << " redirected by presence server";
	}

	void onUnload() override {
	}

	void route(const shared_ptr<MsgSip>& msgSip) {
		LOGI << "Routing to [" << mDestRoute.str() << "]";
		ModuleToolbox::cleanAndPrependRoute(this->getAgent(), msgSip->getMsg(), msgSip->getSip(),
		                                    sip_route_create(msgSip->getHome(), mDestRoute.get(), nullptr));
	}
	bool isMessageAPresenceMessage(const MsgSip& ms) {
		const sip_t* sip = ms.getSip();
		if (sip->sip_request->rq_method == sip_method_subscribe) {
			sip_supported_t* supported;
			bool support_list_subscription = false;
			for (supported = (sip_supported_t*)sip->sip_supported; supported != NULL;
			     supported = (sip_supported_t*)supported->k_next) {
				if (*supported->k_items && strcasecmp((const char*)*supported->k_items, "eventlist") == 0) {
					support_list_subscription = true;
				}
			}
			return (!mOnlyListSubscription->eval(*sip) || support_list_subscription) && sip->sip_event &&
			       strcmp(sip->sip_event->o_type, "presence") == 0;
		} else if (sip->sip_request->rq_method == sip_method_publish) {
			return sip->sip_event && strcmp(sip->sip_event->o_type, "presence") == 0;
		}
		return false;
	}

	unique_ptr<RequestSipEvent> onRequest(unique_ptr<RequestSipEvent>&& ev) override {
		const auto& msgSip = ev->getMsgSip();
		if (isMessageAPresenceMessage(*msgSip)) route(msgSip);
		return std::move(ev);
	}
	unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	}

	ModulePresence(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
		su_home_init(&mHome);
	}

public:
	~ModulePresence() {
		su_home_deinit(&mHome);
	}
};

ModuleInfo<ModulePresence> ModulePresence::sInfo(
    "Presence",
    "This module transfers SIP presence messages, like subscribe/notify/publish to a presence server.",
    {"GatewayAdapter"},
    ModuleInfoBase::ModuleOid::Presence,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor configs[] = {
	        {
	            String,
	            "presence-server",
	            "A SIP URI where to send all presence related requests.",
	            "sip:127.0.0.1:5065;transport=tcp",
	        },
	        {
	            BooleanExpr,
	            "only-list-subscription",
	            "If true, only manage list subscription.",
	            "false",
	        },
	        {
	            Boolean,
	            "check-domain-in-presence-results",
	            "When getting the list of users with phones, if this setting is enabled, it will limit the results to "
	            "the ones that have the same domain.",
	            "false",
	        },
	        config_item_end};
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    moduleConfig.get<ConfigBooleanExpression>("filter")->setDefault(
	        "is_request && (request.method-name == 'PUBLISH' || request.method-name == 'NOTIFY' || "
	        "request.method-name == 'SUBSCRIBE')");
	    moduleConfig.addChildrenValues(configs);
    });