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

#pragma once

#include <memory>
#include <unordered_map>

#include "auth/auth-scheme.hh"
#include "flexisip/module.hh"

namespace flexisip {
class ModuleAuthorization : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ModuleAuthorization>::create(Agent*);

public:
	void addAuthModule(const std::shared_ptr<AuthScheme>& authModule) {
		mAuthModules[authModule->schemeType()] = authModule;
	};

private:
	ModuleAuthorization(Agent* ag, const ModuleInfoBase* moduleInfo);

	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;

	std::unordered_map<std::string, std::shared_ptr<AuthScheme>> mAuthModules;
};

} // namespace flexisip
