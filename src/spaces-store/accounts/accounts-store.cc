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
#include "flexiapi/schemas/account/call-forwarding.hh"
#include "flexisip/logmanager.hh"

using namespace std::chrono_literals;
using namespace flexisip::flexiapi;

namespace flexisip {

AccountsStore::AccountsStore(const std::string& advancedAccountOptions) {
	mDataManager = FileData::make(advancedAccountOptions);
}

AccountsStore::AccountsStore(const std::shared_ptr<FlexiApi>& flexiApiClient,
                             const std::shared_ptr<sofiasip::SuRoot>& root,
                             std::chrono::milliseconds cacheTimeout,
                             std::chrono::milliseconds unknownTimeout) {
	mDataManager = FAMData::make(flexiApiClient, root, cacheTimeout, unknownTimeout);
}

void AccountsStore::resolveCallTarget(
    const CallTarget& target,
    int maxDepth,
    stl_backports::move_only_function<void(std::optional<ResolvedCallTarget>&&, const int& divertedCnt)>&& callback) {
	if (maxDepth < 0) {
		LOGE << "Invalid maxDepth value";
		callback(std::nullopt, 0);
	}
	// Ask the mDataManager which call diversions are declared for this uri.
	mDataManager->findCallDiversions(
	    target.uri, target.type,
	    [this, target, maxDepth, cb = std::move(callback)](const std::vector<CallForwarding>& diversions) mutable {
		    resolveCallTarget(target, maxDepth, diversions, 0, std::move(cb));
	    });
}

void AccountsStore::resolveCallTarget(const CallTarget& target,
                                      int maxDepth,
                                      const std::vector<CallForwarding>& callDiversions,
                                      int divertedCnt,
                                      stl_backports::move_only_function<void(std::optional<ResolvedCallTarget>&&,
                                                                             const int& divertedCnt)>&& finalCallback) {
	ResolvedCallTarget result{};

	for (const auto& d : callDiversions) {
		if (!d.enabled) continue;
		CallTarget divertedTarget = {d.uriType, d.sip_uri};

		switch (d.type) {
			case CallForwarding::Type::Always: {
				++divertedCnt;
				if (divertedCnt > maxDepth) {
					LOGI << "Maximum number of call diversion has been reached (" << divertedCnt
					     << ") and no candidate is available";
					return finalCallback(std::nullopt, divertedCnt);
				}
				if (divertedTarget.type == UriType::Voicemail) {
					return finalCallback(ResolvedCallTarget{.target = divertedTarget}, divertedCnt);
				}
				// Ask the mDataManager which call diversions are declared for this target.
				mDataManager->findCallDiversions(
				    divertedTarget.uri, divertedTarget.type,
				    [this, divertedTarget, maxDepth, divertedCnt,
				     cb = std::move(finalCallback)](const std::vector<CallForwarding>& diversions) mutable {
					    resolveCallTarget(divertedTarget, maxDepth, diversions, divertedCnt, std::move(cb));
				    });
				return;
			}
			case CallForwarding::Type::NoAnswer: {
				result.divertedMap.emplace(d.type, divertedTarget);
				break;
			}
		}
	}

	if (divertedCnt == maxDepth) {
		result.divertedMap.clear();
	}
	result.target.type = UriType::Account;
	result.target.uri = target.uri;
	return finalCallback(std::move(result), divertedCnt);
}

} // namespace flexisip