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

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "accounts-data-manager.hh"
#include "flexiapi/schemas/advanced-account/advanced-account.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/utils/stl-backports.hh"

namespace flexisip {

class AccountsStore {
public:
	static constexpr std::string_view mLogPrefix{"AccountsStore"};

	AccountsStore(const std::string& advancedAccountOptions);

	/**
	 * Resolve the call diversions until a valid uri is found or max-call-diversion is reached.
	 * This function may suspend the call processing until all call data are available.
	 *
	 * @param uri SipUri of call target
	 * @param type reason for checking if a call diversion is set, must be in ['Always', 'Busy', 'Timeout']
	 * @param callback function to resume call processing
	 */
	void checkCallDiversions(const SipUri& uri,
	                         flexiapi::CallDiversion::Type type,
	                         stl_backports::move_only_function<void(const SipUri&)>&& callback);

	void setMaxCallDiversions(int maxCallDiversions) {
		mMaxCallDiversions = maxCallDiversions;
	}

private:
	void checkPermanentCallDiversion(const SipUri& targetUri,
	                                 const std::vector<flexiapi::CallDiversion>& callDiversions,
	                                 int iDivertedCallCnt,
	                                 stl_backports::move_only_function<void(const SipUri&)>&& finalCallback);

	std::unique_ptr<IDataManager> mDataManager;
	int mMaxCallDiversions{};
};
} // namespace flexisip