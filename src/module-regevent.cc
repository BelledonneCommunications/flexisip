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

#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"
#include "flexisip/utils/sip-uri.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "exceptions/bad-configuration.hh"
#include "module-toolbox.hh"

using namespace std;
using namespace flexisip;

class RegEvent : public Module {
	friend std::shared_ptr<Module> ModuleInfo<RegEvent>::create(Agent*);

private:
	static ModuleInfo<RegEvent> sInfo;
	unique_ptr<SipUri> mDestRoute;
	su_home_t mHome;
	shared_ptr<SipBooleanExpression> mOnlyListSubscription;

	bool isValidNextConfig(const ConfigValue& cv) override {
		GenericStruct* module_config = dynamic_cast<GenericStruct*>(cv.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext()) return true;
		if (cv.getName() == "regevent-server") {
			url_t* uri = url_make(&mHome, cv.getName().c_str());
			if (!uri) {
				SLOGE << getModuleName() << ": wrong destination uri for presence server [" << cv.getName() << "]";
				return false;
			} else {
				su_free(&mHome, uri);
			}
		}
		return true;
	}

	void onLoad(const GenericStruct* mc) override {
		const auto* destRouteParam = mc->get<ConfigString>("regevent-server");
		const auto destRouteStr = destRouteParam->read();
		try {
			mDestRoute.reset(new SipUri(destRouteStr));
		} catch (const sofiasip::InvalidUrlError& e) {
			throw BadConfiguration{"invalid SIP URI ('" + destRouteStr + "') in parameter '" +
			                       destRouteParam->getCompleteName() + "' (" + e.what() + ")"};
		}

		SLOGI << getModuleName() << ": presence server is [" << mDestRoute->str() << "]";
	}

	unique_ptr<RequestSipEvent> onRequest(unique_ptr<RequestSipEvent>&& ev) override {
		sip_t* sip = ev->getSip();
		if (sip->sip_request->rq_method == sip_method_subscribe && strcasecmp(sip->sip_event->o_type, "reg") == 0 &&
		    sip->sip_to->a_tag == nullptr) {
			ModuleToolbox::cleanAndPrependRoute(this->getAgent(), ev->getMsgSip()->getMsg(), ev->getSip(),
			                                    sip_route_create(&mHome, mDestRoute->get(), nullptr));
		}
		return std::move(ev);
	}

	std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	}

	RegEvent(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
		su_home_init(&mHome);
	}

public:
	~RegEvent() {
		su_home_deinit(&mHome);
	}
};

ModuleInfo<RegEvent> RegEvent::sInfo(
    "RegEvent",
    "This module is in charge of routing 'reg' event SUBSCRIBE requests to the flexisip-regevent server.",
    {"Redirect"},
    ModuleInfoBase::ModuleOid::RegEvent,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor configs[] = {
	        {
	            String,
	            "regevent-server",
	            "A SIP URI where to send all the reg-event related requests.",
	            "sip:127.0.0.1:6065;transport=tcp",
	        },
	        config_item_end,
	    };
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    moduleConfig.addChildrenValues(configs);
    });