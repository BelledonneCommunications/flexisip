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

#include "domains-store.hh"

using namespace std;

namespace flexisip {

namespace {

constexpr auto kDynamicDomainPath = "/api/spaces";

}

DynamicDomainsStore::DynamicDomainsStore(const shared_ptr<sofiasip::SuRoot>& root,
                                         RestClient&& restClient,
                                         chrono::milliseconds delay)
    : mFAMClient{std::move(restClient)}, mTimer(root, delay) {
	mTimer.setForEver([this] { askAccountManager(); });
	askAccountManager();
}

void DynamicDomainsStore::askAccountManager() {
	mFAMClient.get(
	    kDynamicDomainPath,
	    [this](const std::shared_ptr<HttpMessage>&, const std::shared_ptr<HttpResponse>& rep) {
		    onAccountManagerResponse(rep);
	    },
	    [logPrefix = mLogPrefix](const std::shared_ptr<HttpMessage>&) {
		    LOGE_CTX(logPrefix, "onAccountManagerResponseFailure")
		        << "Received an error while connecting to the account manager, please check your configuration";
	    });
}

void DynamicDomainsStore::onAccountManagerResponse(const std::shared_ptr<HttpResponse>& rep) {
	if (rep->getStatusCode() != 200) {
		LOGE << "Received error " << rep->getStatusCode()
		     << ", please check your api key validity and that the account manager is running properly";
		return;
	}

	try {
		const auto spaces = nlohmann::json::parse(string(rep->getBody().data(), rep->getBody().size()));
		if (!spaces.is_array()) {
			LOGE << "Domains not updated, failed to read spaces";
			return;
		}

		constexpr auto domain = "domain"sv;
		unordered_set<string> domains{};

		for (auto i = 0; i < (int)spaces.size(); ++i) {
			const auto& space = spaces[i];
			if (!space.contains(domain) || !space[domain].is_string()) {
				LOGE << "Domains not updated, expect to have a domain in each space";
				return;
			}
			domains.emplace(space[domain]);
		}

		mDomains = domains;
		LOGD << "Domains updated";
		if (mDomains.empty()) LOGW << "Domains list is empty (expect all requests to be rejected!)";
	} catch (const exception& e) {
		LOGE << "Unexpected error while parsing response: " << e.what();
	}
}

} // namespace flexisip