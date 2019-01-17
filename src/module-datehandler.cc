/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010  Belledonne Communications SARL.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTIC<ULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <flexisip/module.hh>
#include <flexisip/agent.hh>

#include <sofia-sip/msg_addr.h>

using namespace std;
using namespace flexisip;

class DateHandler : public Module, protected ModuleToolbox {
public:
	DateHandler(Agent *ag) : Module(ag) {}
	~DateHandler() {}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev) {
		if (mCommand.empty())
			return;
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (sip->sip_date) {
			char command[256];
			snprintf(command, sizeof(command) - 1, "%s %lu", mCommand.c_str(), sip->sip_date->d_time);
			int err = system(command);
			if (err == -1) {
				LOGE("Command invocation '%s' failed: %s", command, strerror(errno));
			}
		}
	}

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev) {}

protected:
	virtual void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor items[] = {{String, "assign-date-command",
										 "Path to script to assign Date to system. The date is passed as first "
										 "argument of the command, as number of seconds since January 1st, 1900.",
										 ""},
										config_item_end};
		module_config->get<ConfigBoolean>("enabled")->setDefault("false");
		module_config->get<ConfigBooleanExpression>("filter")
			->setDefault("is_request && request.method-name == 'REGISTER'");
		module_config->addChildrenValues(items);
	}
	virtual void onLoad(const GenericStruct *root) {
		mCommand = root->get<ConfigString>("assign-date-command")->read();
	}

private:
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
	{ "Authentication" },
	ModuleInfoBase::ModuleOid::DateHandler,
	ModuleClass::Experimental
);
