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

#include <flexisip/logmanager.hh>
#include <flexisip/module.hh>
#include <flexisip/utils/sip-uri.hh>

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

using namespace std;
using namespace flexisip;

class ModulePresence : public Module, ModuleToolbox {
private:
	static ModuleInfo<ModulePresence> sInfo;
	SipUri mDestRoute;
	su_home_t mHome;
	shared_ptr<SipBooleanExpression> mOnlyListSubscription;

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
			{String, "presence-server",
				"A SIP URI where to send all presence related requests.",
				"sip:127.0.0.1:5065;transport=tcp",
			},
			{BooleanExpr, "only-list-subscription",
				"If true, only manage list subscription.",
				"false"
			},
			{Boolean, "check-domain-in-presence-results",
				"When getting the list of users with phones, if this setting is enabled, it will limit the results to "
				"the ones that have the same domain.",
				"false"
			},
			config_item_end
		};
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");
		module_config->get<ConfigBooleanExpression>("filter")
			->setDefault("is_request && (request.method-name == 'PUBLISH' || request.method-name == 'NOTIFY' || "
						 "request.method-name == 'SUBSCRIBE')");
		module_config->addChildrenValues(configs);
	}

	bool isValidNextConfig(const ConfigValue &cv) {
		GenericStruct *module_config = dynamic_cast<GenericStruct *>(cv.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext())
			return true;
		if (cv.getName() == "presence-server") {
			url_t *uri = url_make(&mHome, cv.getName().c_str());
			if (!uri) {
				SLOGE << getModuleName() << ": wrong destination uri for presence server [" << cv.getName() << "]";
				return false;
			} else {
				su_free(&mHome, uri);
			}
		}
		return true;
	}

	void onLoad(const GenericStruct *mc) {
		auto presenceServerSetting = mc->get<ConfigString>("presence-server");
		auto destRouteStr = presenceServerSetting->read();
		if (destRouteStr.empty()) LOGF("[%s] parameter must be set", presenceServerSetting->getCompleteName().c_str());
		try {
			mDestRoute = SipUri(destRouteStr);
		} catch (const invalid_argument &e) {
			LOGF("Invalid SIP URI (%s) in 'presence-server' parameter of 'Presence' module: %s", destRouteStr.c_str(), e.what());
		}

		mOnlyListSubscription = mc->get<ConfigBooleanExpression>("only-list-subscription")->read();
		SLOGI << getModuleName() << ": presence server is [" << mDestRoute.str() << "]";
		SLOGI << getModuleName() << ": Non list subscription are " << (mOnlyListSubscription ? "not" : "")
			<< " redirected by presence server";
	}

	void onUnload() {
	}

	void route(shared_ptr<RequestSipEvent> &ev) {
		SLOGI << getModuleName() << " routing to [" << mDestRoute.str() << "]";
		cleanAndPrependRoute(this->getAgent(), ev->getMsgSip()->getMsg(), ev->getSip(),
							 sip_route_create(ev->getMsgSip()->getHome(), mDestRoute.get(), nullptr));
	}
	bool isMessageAPresenceMessage(shared_ptr<RequestSipEvent> &ev) {
		sip_t *sip = ev->getSip();
		if (sip->sip_request->rq_method == sip_method_subscribe) {
			sip_supported_t *supported;
			bool support_list_subscription = false;
			for (supported = (sip_supported_t *)sip->sip_supported; supported != NULL;
				 supported = (sip_supported_t *)supported->k_next) {
				if (*supported->k_items && strcasecmp((const char *)*supported->k_items, "eventlist") == 0) {
					support_list_subscription = true;
				}
			}
			return (!mOnlyListSubscription->eval(*ev->getSip()) || support_list_subscription) &&
				sip->sip_event && strcmp(sip->sip_event->o_type, "presence") == 0;
		} else if (sip->sip_request->rq_method == sip_method_publish) {
			return sip->sip_event && strcmp(sip->sip_event->o_type, "presence") == 0;
		}
		return false;
	}

	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		if (isMessageAPresenceMessage(ev))
			route(ev);
	}
	void onResponse([[maybe_unused]] std::shared_ptr<ResponseSipEvent> &ev) {};

public:
	ModulePresence(Agent *ag) : Module(ag) {
		su_home_init(&mHome);
	}

	~ModulePresence() {
		su_home_deinit(&mHome);
	}
};

ModuleInfo<ModulePresence> ModulePresence::sInfo(
	"Presence",
	"This module transfers SIP presence messages, like subscribe/notify/publish to a presence server.",
	{ "GatewayAdapter" },
	ModuleInfoBase::ModuleOid::Presence
);
