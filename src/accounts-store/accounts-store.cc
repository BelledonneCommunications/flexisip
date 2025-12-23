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

#include "exceptions/bad-configuration.hh"
#include "file-data.hh"
#include "flexisip/logmanager.hh"

using namespace flexisip::flexiapi;
namespace flexisip {
namespace {
SipUri findPermanentCallDiversion(const std::vector<CallDiversion>& callDiversions) {
	for (const auto& d : callDiversions) {
		if (d.type == CallDiversion::Type::Always) return d.target;
	}
	return {};
}
} // namespace

AccountsStore::AccountsStore(const std::string& advancedAccountOptions) {
	if (advancedAccountOptions == "flexiapi") throw BadConfiguration("'flexiapi' is not yet implemented");
	mDataManager = std::make_unique<FileData>(advancedAccountOptions);
}

void AccountsStore::checkCallDiversions(const SipUri& uri,
                                        CallDiversion::Type type,
                                        stl_backports::move_only_function<void(const SipUri&)>&& callback) {
	switch (type) {
		case CallDiversion::Type::Always:
		default:
			checkPermanentCallDiversion(uri, {}, 0, std::move(callback));
	}
}

void AccountsStore::checkPermanentCallDiversion(
    const SipUri& targetUri,
    const std::vector<CallDiversion>& callDiversions,
    int iDivertedCallCnt,
    stl_backports::move_only_function<void(const SipUri&)>&& finalCallback) {

	auto divertedUri = iDivertedCallCnt == 0 ? targetUri : findPermanentCallDiversion(callDiversions);

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
	    divertedUri, [this, divertedUri, cnt = iDivertedCallCnt + 1,
	                  callback = std::move(finalCallback)](const std::vector<CallDiversion>& nextDiversions) mutable {
		    checkPermanentCallDiversion(divertedUri, nextDiversions, cnt, std::move(callback));
	    });
}

} // namespace flexisip