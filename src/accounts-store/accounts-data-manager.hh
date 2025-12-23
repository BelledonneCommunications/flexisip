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

#include <string>
#include <unordered_set>
#include <vector>

#include "flexiapi/schemas/advanced-account/advanced-account.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/utils/stl-backports.hh"

namespace flexisip {
struct AccountsData {
	struct hash {
		size_t operator()(const flexiapi::AccountParam& a) const {
			std::string uri = a.sip_uri.getUser() + "@" + a.sip_uri.getHost();
			return std::hash<std::string>{}(uri);
		};
	};
	std::unordered_set<flexiapi::AccountParam, hash> mAccounts;
};

class IDataManager {
public:
	virtual ~IDataManager() = default;
	virtual void fetchAccount(const SipUri& uri) = 0;
	virtual void findCallDiversions(
	    const SipUri& uri,
	    stl_backports::move_only_function<void(const std::vector<flexiapi::CallDiversion>&)>&& callback) = 0;
};
} // namespace flexisip