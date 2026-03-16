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

#include <chrono>

#include "fam-data.hh"
#include "file-data.hh"
#include "flexiapi/config.hh"
#include "flexisip/logmanager.hh"

using namespace std::chrono_literals;
using namespace flexisip::flexiapi;

namespace flexisip {
namespace {
std::pair<SipUri, CallForwarding::ForwardType>
findPermanentCallDiversion(const std::vector<CallForwarding>& callDiversions) {
	for (const auto& d : callDiversions) {
		if (d.enabled && d.type == CallForwarding::Type::Always) {
			switch (d.forward_to) {
				using enum CallForwarding::ForwardType;
				case Contact:
				case SipUri:
					return {d.sip_uri, d.forward_to};
				case Voicemail:
					return {flexisip::SipUri{}, d.forward_to};
			}
		}
	}
	return {SipUri{}, CallForwarding::ForwardType::SipUri};
}
} // namespace

AccountsStore::AccountsStore(const std::string& advancedAccountOptions,
                             const std::shared_ptr<ConfigManager>& configManager,
                             const std::shared_ptr<Http2Client>& flexiApiClient,
                             const std::shared_ptr<sofiasip::SuRoot>& root) {
	if (advancedAccountOptions == "flexiapi") {
		mDataManager = std::make_unique<FAMData>(createRestClient(*configManager, flexiApiClient), root, 30s, 10min);
		return;
	}
	mDataManager = std::make_unique<FileData>(advancedAccountOptions);
}

void AccountsStore::checkCallDiversions(const SipUri& uri,
                                        CallForwarding::Type type,
                                        stl_backports::move_only_function<void(const SipUri&)>&& callback) {
	switch (type) {
		case CallForwarding::Type::Always:
		default:
			checkPermanentCallDiversion(uri, {}, 0, std::move(callback));
	}
}

void AccountsStore::checkPermanentCallDiversion(
    const SipUri& targetUri,
    const std::vector<CallForwarding>& callDiversions,
    int iDivertedCallCnt,
    stl_backports::move_only_function<void(const SipUri&)>&& finalCallback) {

	auto [divertedUri, divertedType] = iDivertedCallCnt == 0 ? std::pair{targetUri, CallForwarding::ForwardType::SipUri}
	                                                         : findPermanentCallDiversion(callDiversions);

	if (divertedType == CallForwarding::ForwardType::Voicemail) {
		LOGE << "Voicemail call diversion is not supported yet";
		return finalCallback({});
	}
	if (divertedUri.empty()) {
		return finalCallback(targetUri);
	}
	if (iDivertedCallCnt > mMaxCallDiversions) {
		LOGI << "Stopping call because the maximum number of call diversion has been reached and no candidate is "
		        "available";
		return finalCallback({});
	}

	LOGD << "Find if '" << divertedUri.str() << "' has a 'Always' type call diversion";
	mDataManager->findCallDiversions(
	    divertedUri, divertedType,
	    [this, divertedUri, cnt = iDivertedCallCnt + 1,
	     callback = std::move(finalCallback)](const std::vector<CallForwarding>& nextDiversions) mutable {
		    checkPermanentCallDiversion(divertedUri, nextDiversions, cnt, std::move(callback));
	    });
}

} // namespace flexisip