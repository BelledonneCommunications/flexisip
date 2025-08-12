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

#include <chrono>
#include <list>
#include <memory>
#include <unordered_set>

#include "auth/auth-scheme.hh"
#include "flexisip/module.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip {
class ModuleAuthorization : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ModuleAuthorization>::create(Agent*);

public:
	void addAuthModule(const std::shared_ptr<AuthScheme>& authModule) {
		mAuthModules[authModule->schemeType()] = authModule;
	};

private:
	ModuleAuthorization(Agent* ag, const ModuleInfoBase* moduleInfo);

	void onLoad(const GenericStruct* mc) override;
	std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override;

	class IDomainManager {
	public:
		virtual ~IDomainManager() = default;
		virtual const std::unordered_set<std::string>& getAuthorizedDomains() = 0;
	};

	class StaticDomainManger : public IDomainManager {
	public:
		StaticDomainManger(const std::list<std::string>& domains) {
			for (const auto& domain : domains)
				mAuthorizedDomains.emplace(domain);
		}
		const std::unordered_set<std::string>& getAuthorizedDomains() override {
			return mAuthorizedDomains;
		};

	private:
		std::unordered_set<std::string> mAuthorizedDomains;
	};

	class DynamicDomainManager : public IDomainManager {
	public:
		DynamicDomainManager(const std::shared_ptr<sofiasip::SuRoot>& root,
		                     const std::string& host,
		                     const std::string& port,
		                     const std::string& apiKey,
		                     std::chrono::milliseconds delay);

		const std::unordered_set<std::string>& getAuthorizedDomains() override {
			return mAuthorizedDomains;
		};

	private:
		void askAccountManager();
		void onAccountManagerResponse(const std::shared_ptr<HttpResponse>& rep);

		std::string mLogPrefix;
		RestClient mFAMClient;
		sofiasip::Timer mTimer;
		std::unordered_set<std::string> mAuthorizedDomains;
	};

	std::unordered_map<std::string, std::shared_ptr<AuthScheme>> mAuthModules;
	std::unique_ptr<IDomainManager> mDomainManager;
};

} // namespace flexisip