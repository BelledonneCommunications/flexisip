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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "accounts-data-manager.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/utils/stl-backports.hh"
#include "utils/transport/http/http2client.hh"

namespace flexisip {

class AccountsStore {
public:
	static constexpr std::string_view mLogPrefix{"AccountsStore"};

	enum class TargetType {
		Account,
		// Group,
		Voicemail,
	};
	struct CallTarget {
		TargetType type;
		SipUri uri;
	};
	using CallDiversionMap = std::unordered_map<int, CallTarget>;
	struct ResolvedCallTarget {
		CallTarget target{};
		CallDiversionMap divertedMap{};
	};

	AccountsStore(const std::string& advancedAccountOptions,
	              const std::shared_ptr<ConfigManager>& configManager,
	              const std::shared_ptr<Http2Client>& flexiApiClient,
	              const std::shared_ptr<sofiasip::SuRoot>& root);

	/**
	 * Resolve the call diversions until a valid uri is found or the maximum depth is reached.
	 * This function may suspend the call processing until all call data is available.
	 *
	 * @param uri SipUri of initial target
	 * @param maxDepth maximum depth to resolve diversions
	 * @param callback function to resume call processing
	 */
	void resolveCallTarget(SipUri uri,
	                       int maxDepth,
	                       stl_backports::move_only_function<void(std::optional<ResolvedCallTarget>&&,
	                                                              const int& divertedCnt)>&& callback);

private:
	// Fetch the call diversions declared for `uri`, then resolve them.
	void resolveCallTarget(const SipUri& uri,
	                       int maxDepth,
	                       const std::vector<flexiapi::CallForwarding>& callDiversions,
	                       int divertedCnt,
	                       stl_backports::move_only_function<void(std::optional<ResolvedCallTarget>&&,
	                                                              const int& divertedCnt)>&& finalCallback);

	// Only one instance, but shared to track lifetime.
	std::shared_ptr<IDataManager> mDataManager;
};
} // namespace flexisip