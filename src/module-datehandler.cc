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

#include <sofia-sip/msg_addr.h>

#include <flexisip/module.hh>

#include "agent.hh"

using namespace std;
using namespace flexisip;

class DateHandler : public Module {
	friend std::shared_ptr<Module> ModuleInfo<DateHandler>::create(Agent*);

public:
	~DateHandler() {
	}

	unique_ptr<RequestSipEvent> onRequest(unique_ptr<RequestSipEvent>&& ev) override {
		if (mCommand.empty()) return std::move(ev);
		const shared_ptr<MsgSip>& ms = ev->getMsgSip();
		sip_t* sip = ms->getSip();
		if (sip->sip_date) {
			char command[256];
			snprintf(command, sizeof(command) - 1, "%s %lu", mCommand.c_str(), sip->sip_date->d_time);
			int err = system(command);
			if (err == -1) {
				LOGE << "Command invocation '" << command << "' failed: " << strerror(errno);
			}
		}
		return std::move(ev);
	}

	unique_ptr<ResponseSipEvent> onResponse(unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	}

protected:
	void onLoad(const GenericStruct* root) override {
		mCommand = root->get<ConfigString>("assign-date-command")->read();
	}

private:
	DateHandler(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	}

	string mCommand;
	static ModuleInfo<DateHandler> sInfo;
};

ModuleInfo<DateHandler> DateHandler::sInfo(
    "DateHandler",
    "The purpose of the DateHandler module is to catch 'Date' "
    "headers from sip requests, and call config-defined script "
    "passing it the date value. The typical use case "
    "is for deploying a Flexisip proxy in an embedded system "
    "that doesn't have time information when booting up. The "
    "command can be used to assign the date to the system.",
    {"Authentication, Authorization"},
    ModuleInfoBase::ModuleOid::DateHandler,

    [](GenericStruct& moduleConfig) {
	    ConfigItemDescriptor items[] = {
	        {
	            String,
	            "assign-date-command",
	            "Path to script to assign Date to system. The date is passed as first "
	            "argument of the command, as number of seconds since January 1st, 1900.",
	            "",
	        },
	        config_item_end,
	    };
	    moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	    moduleConfig.get<ConfigBooleanExpression>("filter")->setDefault(
	        "i_request && request.method-name == 'REGISTER'");
	    moduleConfig.addChildrenValues(items);
    },

    ModuleClass::Experimental);