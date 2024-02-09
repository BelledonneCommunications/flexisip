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

#include <flexisip/module.hh>

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

using namespace std;
using namespace flexisip;

class ModuleGarbageIn : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ModuleGarbageIn>::create(Agent*);

public:
	~ModuleGarbageIn() {
	}

	virtual void onRequest(shared_ptr<RequestSipEvent>& ev) {
		SLOGD << "Garbage: processing terminated";
		ev->terminateProcessing();
	}

	virtual void onResponse(shared_ptr<ResponseSipEvent>& ev) {
		SLOGD << "Garbage: processing terminated";
		ev->terminateProcessing();
	}

private:
	ModuleGarbageIn(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	}

	static ModuleInfo<ModuleGarbageIn> sInfo;
};

ModuleInfo<ModuleGarbageIn>
    ModuleGarbageIn::sInfo("GarbageIn",
                           "The GarbageIn module collects incoming garbage and prevent any further processing.",
                           {"SanityChecker"},
                           ModuleInfoBase::ModuleOid::GarbageIn,

                           [](GenericStruct& moduleConfig) {
	                           moduleConfig.get<ConfigBoolean>("enabled")->setDefault("false");
	                           moduleConfig.get<ConfigValue>("filter")->setDefault("false");
                           });
