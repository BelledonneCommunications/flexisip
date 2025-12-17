/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module.hh"

#include "agent.hh"

using namespace flexisip;

class ModuleSanityChecker : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ModuleSanityChecker>::create(Agent*);

public:
	~ModuleSanityChecker() override = default;

	std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override;

	std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override {
		// don't check our responses ;)
		return std::move(ev);
	}

private:
	ModuleSanityChecker(Agent* ag, const ModuleInfoBase* moduleInfo) : Module(ag, moduleInfo) {
	}

	void checkHeaders(sip_t* sip);

	static ModuleInfo<ModuleSanityChecker> sInfo;
};
