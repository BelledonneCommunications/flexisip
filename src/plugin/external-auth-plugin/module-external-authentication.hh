/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <array>
#include <regex>

#include <flexisip/agent.hh>
#include <flexisip/module-authentication-base.hh>

#include "external-auth-module.hh"

namespace flexisip {

class ModuleExternalAuthentication : public ModuleAuthenticationBase {
public:
	ModuleExternalAuthentication(Agent *agent) : ModuleAuthenticationBase(agent) {}
	~ModuleExternalAuthentication() override = default;

private:
	void onDeclare(GenericStruct *mc) override;
	void onLoad(const GenericStruct *root) override;

	std::unique_ptr<Authentifier> createAuthModule(int nonceExpire, bool qopAuth) override;

	void onSuccess(const Authentifier::AuthStatus &as) override;
	void errorReply(const Authentifier::AuthStatus &as) override;

	std::map<nth_client_t *, std::shared_ptr<RequestSipEvent>> mPendingEvent;
	std::string mRemoteUri;
};

}
