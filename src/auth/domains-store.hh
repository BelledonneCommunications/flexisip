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

#pragma once

#include <chrono>
#include <list>
#include <memory>
#include <string>
#include <unordered_set>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip {

class IDomainsStore {
public:
	virtual ~IDomainsStore() = default;
	virtual const std::unordered_set<std::string>& getDomains() = 0;
};

class StaticDomainsStore : public IDomainsStore {
public:
	explicit StaticDomainsStore(const std::list<std::string>& domains) {
		for (const auto& domain : domains)
			mDomains.emplace(domain);
	}

	const std::unordered_set<std::string>& getDomains() override {
		return mDomains;
	};

private:
	static constexpr std::string_view mLogPrefix{"StaticDomainsStore"};

	std::unordered_set<std::string> mDomains;
};

class DynamicDomainsStore : public IDomainsStore {
public:
	DynamicDomainsStore(const std::shared_ptr<sofiasip::SuRoot>& root,
	                    RestClient&& restClient,
	                    std::chrono::milliseconds delay);

	const std::unordered_set<std::string>& getDomains() override {
		return mDomains;
	};

private:
	static constexpr std::string_view mLogPrefix{"DynamicDomainsStore"};

	void askAccountManager();
	void onAccountManagerResponse(const std::shared_ptr<HttpResponse>& rep);

	RestClient mFAMClient;
	sofiasip::Timer mTimer;
	std::unordered_set<std::string> mDomains;
};

} // namespace flexisip