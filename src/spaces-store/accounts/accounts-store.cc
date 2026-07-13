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

#include "accounts-store.hh"

#include "fam-data.hh"
#include "file-data.hh"
#include "flexiapi/config.hh"
#include "flexiapi/schemas/account/call-forwarding.hh"
#include "flexisip/logmanager.hh"
#include "utils/uri-utils.hh"

using namespace std::chrono_literals;
using namespace flexisip::flexiapi;

namespace flexisip {

AccountsStore::AccountsStore(const std::string& advancedAccountOptions,
                             const std::shared_ptr<ConfigManager>& configManager,
                             const std::shared_ptr<Http2Client>& flexiApiClient,
                             const std::shared_ptr<sofiasip::SuRoot>& root) {
	if (advancedAccountOptions == "flexiapi") {
		mDataManager = FAMData::make(createRestClient(*configManager, flexiApiClient), root, 30s, 10min);
		return;
	}
	mDataManager = std::make_shared<FileData>(advancedAccountOptions);
}

void AccountsStore::resolveCallTarget(
    SipUri uri,
    int maxDepth,
    stl_backports::move_only_function<void(std::optional<ResolvedCallTarget>&&, const int& divertedCnt)>&& callback) {
	if (maxDepth < 0) {
		LOGE << "Invalid maxDepth value";
		callback(std::nullopt, 0);
	}
	// Ask the mDataManager which call diversions are declared for this uri.
	mDataManager->findCallDiversions(
	    uri, CallForwarding::ForwardType::SipUri,
	    [this, uri, maxDepth, cb = std::move(callback)](const std::vector<CallForwarding>& diversions) mutable {
		    resolveCallTarget(uri, maxDepth, diversions, 0, std::move(cb));
	    });
}

void AccountsStore::resolveCallTarget(const SipUri& uri,
                                      int maxDepth,
                                      const std::vector<CallForwarding>& callDiversions,
                                      int divertedCnt,
                                      stl_backports::move_only_function<void(std::optional<ResolvedCallTarget>&&,
                                                                             const int& divertedCnt)>&& finalCallback) {
	ResolvedCallTarget result;

	for (const auto& d : callDiversions) {
		if (!d.enabled) continue;
		switch (d.type) {
			case CallForwarding::Type::Always: {
				++divertedCnt;
				if (divertedCnt > maxDepth) {
					LOGI << "Maximum number of call diversion has been reached (" << divertedCnt
					     << ") and no candidate is available";
					return finalCallback(std::nullopt, divertedCnt);
				}
				if (d.forward_to == CallForwarding::ForwardType::Voicemail) {
					return finalCallback(ResolvedCallTarget{.target = {TargetType::Voicemail}}, divertedCnt);
				}
				// Ask the mDataManager which call diversions are declared for this uri.
				mDataManager->findCallDiversions(
				    d.sip_uri, d.forward_to,
				    [this, uri = d.sip_uri, maxDepth, divertedCnt,
				     cb = std::move(finalCallback)](const std::vector<CallForwarding>& diversions) mutable {
					    resolveCallTarget(uri, maxDepth, diversions, divertedCnt, std::move(cb));
				    });
				return;
			}
			case CallForwarding::Type::NoAnswer: {
				CallTarget noAnswerTarget{TargetType::Account, d.sip_uri};
				result.divertedMap.emplace(408, noAnswerTarget);
				result.divertedMap.emplace(603, noAnswerTarget);
				break;
			}
			case CallForwarding::Type::Busy: {
				CallTarget busyTarget{TargetType::Account, d.sip_uri};
				result.divertedMap.emplace(486, busyTarget);
				break;
			}
		}
	}

	if (divertedCnt == maxDepth) {
		result.divertedMap.clear();
	}
	result.target.type = TargetType::Account;
	result.target.uri = uri;
	return finalCallback(std::move(result), divertedCnt);
}

} // namespace flexisip