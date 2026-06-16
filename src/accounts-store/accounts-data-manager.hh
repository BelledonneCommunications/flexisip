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

#include <unordered_map>
#include <vector>

#include "flexiapi/schemas/account/account.hh"
#include "flexiapi/schemas/account/call-forwarding.hh"
#include "flexiapi/schemas/api-formatted-uri.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/utils/stl-backports.hh"

namespace flexisip {

class IDataManager {
public:
	using CallDiversionsCallback =
	    stl_backports::move_only_function<void(const std::vector<flexiapi::CallForwarding>&)>;
	using Accounts = std::unordered_map<flexiapi::ApiFormattedUri, flexiapi::Account>;

	virtual ~IDataManager() = default;
	virtual void findCallDiversions(const SipUri& uri,
	                                flexiapi::CallForwarding::ForwardType forwardType,
	                                CallDiversionsCallback&& callback) = 0;
};

} // namespace flexisip