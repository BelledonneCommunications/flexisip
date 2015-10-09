/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2014  Belledonne Communications SARL.

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

#include "module.hh"
#include "agent.hh"
#include "log/logmanager.hh"

using namespace ::std;



class ModulePresence: public Module, ModuleToolbox {

private:
	static ModuleInfo<ModulePresence> sInfo;
	string mDestRoute;
	su_home_t mHome;

	void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor configs[] = {
				{ String, "presence-server", "A sip uri where to send all presence's requests", "sip:127.0.0.1:5065" },
				config_item_end
		};
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");
		module_config->get<ConfigBooleanExpression>("filter")->setDefault("is_request && (request.method-name == 'PUBLISH' || request.method-name == 'NOTIFY' || request.method-name == 'SUBSCRIBE')");
		module_config->addChildrenValues(configs);

	}

	bool isValidNextConfig(const ConfigValue &cv) {
		GenericStruct *module_config=dynamic_cast<GenericStruct*>(cv.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext()) return true;
		if (cv.getName() == "presence-server") {
			url_t* uri=url_make(&mHome, cv.getName().c_str());
			if (!uri) {
				SLOGE<< this->getModuleName() << ": wrong destination uri for presence server [" <<cv.getName() <<"]";
				return false;
			} else {
				 su_free(&mHome, uri);
			}
		}
		return true;
	}


	void onLoad(const GenericStruct *mc) {
		mDestRoute = mc->get<ConfigString>("presence-server")->read();
		SLOGI<< this->getModuleName() << ": presence server is ["<< mDestRoute <<"]";
	}

	void onUnload() {
	}

	void route(shared_ptr<RequestSipEvent> &ev) {
		SLOGI << getModuleName() << " routing to [" << mDestRoute << "]";
		cleanAndPrependRoute(this->getAgent(),ev->getMsgSip()->getMsg(),ev->getSip(),sip_route_make(&mHome,mDestRoute.c_str()));

	}
	bool isMessageAPresenceMessage(shared_ptr<RequestSipEvent> &ev) {
		sip_t* sip=ev->getSip();
		if (strncasecmp(sip->sip_request->rq_method_name,"SUBSCRIBE",strlen(sip->sip_request->rq_method_name)) == 0) {
			return true;
		} else if (strncasecmp(sip->sip_request->rq_method_name,"PUBLISH",strlen(sip->sip_request->rq_method_name)) == 0) {
			return !sip->sip_content_type || (sip->sip_content_type
				&& sip->sip_content_type->c_type && strcasecmp (sip->sip_content_type->c_type,"application/pidf+xml")==0
				&& sip->sip_content_type->c_subtype && strcasecmp (sip->sip_content_type->c_subtype,"pidf+xml")==0);
		}
		return false;
	}
	void onRequest(shared_ptr<RequestSipEvent> &ev) {
		if (isMessageAPresenceMessage(ev))
			route(ev);

	}
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev){};

public:
		ModulePresence(Agent *ag) : Module(ag) {
			su_home_init(&mHome);
		}

		~ModulePresence() {
		}

};
ModuleInfo<ModulePresence> ModulePresence::sInfo("Presence",
		"This module transfert sip presence messages, like subscribe/notify/publish to a presence server. ",
		ModuleInfoBase::ModuleOid::Presence,
		ModuleTypeExperimental);

