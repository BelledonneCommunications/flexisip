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

#pragma once

#include <array>
#include <regex>

#include <flexisip/module-authentication-base.hh>

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "external-auth-module.hh"

namespace flexisip {

class ModuleExternalAuthentication : public ModuleAuthenticationBase {
	friend std::shared_ptr<Module> ModuleInfo<ModuleExternalAuthentication>::create(Agent*);

public:
	~ModuleExternalAuthentication() override = default;

private:
	ModuleExternalAuthentication(Agent* agent, const ModuleInfoBase* moduleInfo)
	    : ModuleAuthenticationBase(agent, moduleInfo) {
	}

	void onLoad(const GenericStruct* root) override;

	FlexisipAuthModuleBase* createAuthModule(const std::string& domain, int nonceExpire, bool qopAuth) override;
	FlexisipAuthStatus* createAuthStatus(const std::shared_ptr<MsgSip>& msgSip) override;

	void onSuccess(const FlexisipAuthStatus& as) override;
	void errorReply(RequestSipEvent& ev, const FlexisipAuthStatus& as) override;

	std::string mRemoteUri;
};

} // namespace flexisip