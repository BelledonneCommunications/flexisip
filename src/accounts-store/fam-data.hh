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

#include <filesystem>
#include <queue>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "accounts-data-manager.hh"
#include "flexiapi/flexiapi.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "flexisip/utils/sip-uri.hh"
#include "utils/transport/http/http-response.hh"

namespace flexisip {

class FAMData : public IDataManager {
	using HttpRequest = HttpMessage;

public:
	FAMData(RestClient&& restClient,
	        const std::shared_ptr<sofiasip::SuRoot>& root,
	        std::chrono::milliseconds cacheTimeout,
	        std::chrono::milliseconds unknownTimeout);
	void findCallDiversions(const SipUri& uri,
	                        flexiapi::CallForwarding::ForwardType forwardType,
	                        CallDiversionsCallback&& callback) override;

private:
	static constexpr std::string_view mLogPrefix{"AccountsStore::FAMData"};

	void onResponseCallback(const std::shared_ptr<HttpRequest>&,
	                        const std::shared_ptr<HttpResponse>& response,
	                        const flexiapi::ApiFormattedUri& apiUri,
	                        const flexiapi::UriType& uriType);
	void onErrorCallback(const std::shared_ptr<HttpRequest>& response, const flexiapi::ApiFormattedUri& apiUri);

	void notifyWaitingCallbacks(const flexiapi::ApiFormattedUri& apiUri,
	                            const std::vector<flexiapi::CallForwarding>& diversions);
	void startCacheTimer(const flexiapi::ApiFormattedUri& apiUri);
	void startUnknownTimer(const flexiapi::ApiFormattedUri& apiUri);

	flexiapi::FlexiApi mFlexiApiClient;
	Accounts mAccounts;
	std::shared_ptr<sofiasip::SuRoot> mRoot;
	std::unordered_map<flexiapi::ApiFormattedUri, std::queue<CallDiversionsCallback>> mWaitingAccounts;
	std::unordered_set<flexiapi::ApiFormattedUri> mUnknownAccounts;
	std::unordered_map<flexiapi::ApiFormattedUri, sofiasip::Timer> mCacheTimers;
	std::unordered_map<flexiapi::ApiFormattedUri, sofiasip::Timer> mUnknownTimers;
	std::chrono::milliseconds mCacheTimeout;
	std::chrono::milliseconds mUnknownTimeout;
};

} // namespace flexisip
