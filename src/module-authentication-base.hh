/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010 Belledonne Communications SARL, All rights reserved.

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

#include <list>
#include <map>
#include <memory>
#include <regex>
#include <string>

#include "flexisip/module.hh"

#include "auth/flexisip-auth-module-base.hh"

namespace flexisip {

class ModuleAuthenticationBase : public Module {
public:
	ModuleAuthenticationBase(Agent *agent);
	~ModuleAuthenticationBase() = default;

protected:
	void onDeclare(GenericStruct *root) override;
	void onLoad(const GenericStruct *root) override;
	void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override {}

	virtual FlexisipAuthModuleBase *createAuthModule(const std::string &domain, const std::string &algorithm) = 0;
	virtual FlexisipAuthModuleBase *createAuthModule(const std::string &domain, const std::string &algorithm, int nonceExpire) = 0;
	virtual FlexisipAuthStatus *createAuthStatus(const std::shared_ptr<RequestSipEvent> &ev, const url_t *userUri) = 0;

	void processAuthModuleResponse(AuthStatus &as);
	virtual void onSuccess(const FlexisipAuthStatus &as);
	virtual void errorReply(const FlexisipAuthStatus &as) = 0;

	FlexisipAuthModuleBase *findAuthModule(const std::string name);
	void configureAuthStatus(FlexisipAuthStatus &as, const std::shared_ptr<RequestSipEvent> &ev, const url_t *userUri);

protected:
	std::map<std::string, std::unique_ptr<FlexisipAuthModuleBase>> mAuthModules;
	std::list<std::string> mAlgorithms;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	std::string mRealmRegexStr;
	std::regex mRealmRegex;
};

}
