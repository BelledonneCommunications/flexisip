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

#include <sofia-sip/sip_status.h>

#include "flexisip/logmanager.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

using namespace std;
using namespace flexisip;

class ModuleRedirect : public Module, ModuleToolbox {
private:
	static ModuleInfo<ModuleRedirect> sInfo;
	sip_contact_t* mContact;
	su_home_t mHome;

	void onDeclare(GenericStruct* module_config) {
		ConfigItemDescriptor configs[] = {
		    {String, "contact", "A contact where to redirect requests. ex: <sip:127.0.0.1:5065>;expires=100", ""},
		    config_item_end};
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");
		module_config->addChildrenValues(configs);
	}

	bool isValidNextConfig(const ConfigValue& cv) {
		GenericStruct* module_config = dynamic_cast<GenericStruct*>(cv.getParent());
		if (!module_config->get<ConfigBoolean>("enabled")->readNext()) return true;
		if (cv.getName() == "contact") {
			sip_contact_t* contact = sip_contact_make(&mHome, cv.getName().c_str());
			if (!contact) {
				SLOGE << this->getModuleName() << ": wrong destination contact for redirection [" << cv.getName()
				      << "]";
				return false;
			}
		}
		return true;
	}

	void onLoad(const GenericStruct* mc) {
		mContact = sip_contact_make(&mHome, mc->get<ConfigString>("contact")->read().c_str());
		SLOGI << this->getModuleName() << ": redirect contact is [" << mc->get<ConfigString>("contact")->read().c_str()
		      << "]";
	}

	void onUnload() {
	}

	void onRequest(shared_ptr<RequestSipEvent>& ev) {
		ev->reply(SIP_302_MOVED_TEMPORARILY, SIPTAG_CONTACT(sip_contact_dup(&mHome, mContact)),
		          SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
	void onResponse([[maybe_unused]] std::shared_ptr<ResponseSipEvent>& ev){};

public:
	ModuleRedirect(Agent* ag) : Module(ag) {
		su_home_init(&mHome);
	}

	~ModuleRedirect() {
		su_home_deinit(&mHome);
	}
};

ModuleInfo<ModuleRedirect> ModuleRedirect::sInfo("Redirect",
                                                 "This module redirect sip requests with a 302 move temporarily.",
                                                 {"DateHandler", "Authentication", "ExternalAuthentication"},
                                                 ModuleInfoBase::ModuleOid::Redirect);
