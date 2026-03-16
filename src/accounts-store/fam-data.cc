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

#include "fam-data.hh"

#include "flexiapi/schemas/account/account-json.hh"

#include "flexisip/logmanager.hh"

using namespace std;
using namespace flexisip::flexiapi;
namespace flexisip {

FAMData::FAMData(RestClient&& restClient,
                 const std::shared_ptr<sofiasip::SuRoot>& root,
                 std::chrono::milliseconds cacheTimeout,
                 std::chrono::milliseconds unknownTimeout)
    : mFlexiApiClient{std::move(restClient)}, mRoot{root}, mCacheTimeout(cacheTimeout),
      mUnknownTimeout(unknownTimeout) {}

void FAMData::findCallDiversions(const SipUri& uri,
                                 CallForwarding::ForwardType forwardType,
                                 CallDiversionsCallback&& callback) {
	const auto apiUri = ApiFormattedUri{uri};

	// If already present use local cache
	if (const auto account = mAccounts.find(apiUri); account != mAccounts.end()) {
		callback(account->second.call_forwardings);
		return;
	}
	// If already known as unknown (404 from fam), early return
	if (mUnknownAccounts.contains(apiUri)) {
		callback({});
		return;
	}
	// If a request is already sent, wait for the answer.
	if (auto waiting = mWaitingAccounts.find(apiUri); waiting != mWaitingAccounts.end()) {
		waiting->second.push(std::move(callback));
		return;
	}

	// Ask FlexiApi
	std::queue<CallDiversionsCallback> q;
	q.push(std::move(callback));
	mWaitingAccounts.try_emplace(apiUri, std::move(q));
	if (forwardType == CallForwarding::ForwardType::Contact) {
		mFlexiApiClient.accountSearchByUri(
		    apiUri,
		    [this, apiUri](const std::shared_ptr<HttpRequest>& req, const std::shared_ptr<HttpResponse>& res) {
			    onResponseCallback(req, res, apiUri, UriType::Account);
		    },
		    [this, apiUri](const std::shared_ptr<HttpRequest>& req) { onErrorCallback(req, apiUri); });
	} else {
		mFlexiApiClient.resolveByUri(
		    apiUri,
		    [this, apiUri](const std::shared_ptr<HttpRequest>& req, const std::shared_ptr<HttpResponse>& res) {
			    onResponseCallback(req, res, apiUri, UriType::Unknown);
		    },
		    [this, apiUri](const std::shared_ptr<HttpRequest>& req) { onErrorCallback(req, apiUri); });
	}
}

void FAMData::startCacheTimer(const ApiFormattedUri& apiUri) {
	auto [cacheTimer, inserted] = mCacheTimers.try_emplace(apiUri, mRoot, mCacheTimeout);
	if (inserted) {
		cacheTimer->second.set([this, apiUri] {
			mAccounts.erase(apiUri);
			mCacheTimers.erase(apiUri);
		});
	}
}

void FAMData::startUnknownTimer(const ApiFormattedUri& apiUri) {
	auto [unknownTimer, inserted] = mUnknownTimers.try_emplace(apiUri, mRoot, mUnknownTimeout);
	if (inserted) {
		unknownTimer->second.set([this, apiUri] {
			mUnknownAccounts.erase(apiUri);
			mUnknownTimers.erase(apiUri);
		});
	}
}

void FAMData::onResponseCallback(const std::shared_ptr<HttpRequest>&,
                                 const std::shared_ptr<HttpResponse>& response,
                                 const ApiFormattedUri& apiUri,
                                 const UriType& uriType) {
	if (response.get()->getStatusCode() != 200) {
		if (response.get()->getStatusCode() == 404) {
			LOGI << "Account unknown calling resolve[" << string_view{apiUri} << "] from FlexiAPI.";
			mUnknownAccounts.insert(apiUri);
			startUnknownTimer(apiUri);
		} else {
			LOGW << "Error while calling resolve[" << string_view{apiUri}
			     << "] from FlexiAPI: " << response.get()->getStatusCode();
		}
		notifyWaitingCallbacks(apiUri, {});
		return;
	}
	Account account;
	try {
		if (uriType == UriType::Account) {
			account = nlohmann::json::parse(response->getBodyAsString()).get<Account>();
		} else {
			auto resolvedUri = nlohmann::json::parse(response->getBodyAsString()).get<ResolvedUri>();
			switch (resolvedUri.type) {
				case UriType::Account:
					account = resolvedUri.asAccount();
					break;
				case UriType::Group:
					LOGE << "Group are not yet handled";
					notifyWaitingCallbacks(apiUri, {});
					return;
				default:
					LOGE << "Unknown URI type: " << toString(resolvedUri.type);
					notifyWaitingCallbacks(apiUri, {});
					return;
			}
		}
	} catch (const nlohmann::json::exception& e) {
		LOGE << "Error while parsing response from FlexiAPI: " << e.what();
		notifyWaitingCallbacks(apiUri, {});
		return;
	}

	mAccounts.try_emplace(apiUri, account);
	notifyWaitingCallbacks(apiUri, account.call_forwardings);
	startCacheTimer(apiUri);
}

void FAMData::onErrorCallback(const std::shared_ptr<HttpRequest>&, const ApiFormattedUri& apiUri) {
	LOGE << "Error while trying to call resolve[" << string_view{apiUri} << "] from FlexiAPI";
	notifyWaitingCallbacks(apiUri, {});
}

void FAMData::notifyWaitingCallbacks(const ApiFormattedUri& apiUri, const std::vector<CallForwarding>& diversions) {
	if (auto waiting = mWaitingAccounts.find(apiUri); waiting != mWaitingAccounts.end()) {
		auto queue = std::move(waiting->second);
		mWaitingAccounts.erase(waiting);
		while (!queue.empty()) {
			auto& callback = queue.front();
			try {
				callback(diversions);
			} catch (const std::exception& e) {
				LOGE << "Unhandled exception in callback for [" << string_view{apiUri} << "]: " << e.what();
			}
			queue.pop();
		}
	}
}

} // namespace flexisip
