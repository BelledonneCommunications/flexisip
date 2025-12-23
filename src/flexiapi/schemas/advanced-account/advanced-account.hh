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

#include "flexisip/utils/sip-uri.hh"

namespace flexisip::flexiapi {

enum class UriType {
	Account,
	Group,
};
struct CallDiversion {
	enum class Type {
		Always,
		Busy,
		Away,
	};
	Type type;
	SipUri target{};
	UriType target_type;
};

struct AccountParam {
	AccountParam() = default;
	AccountParam(const SipUri& uri) : sip_uri(uri) {}

	bool operator==(const AccountParam& other) const {
		return sip_uri.getUser() == other.sip_uri.getUser() && sip_uri.getHost() == other.sip_uri.getHost();
	}

	SipUri sip_uri;
	std::vector<CallDiversion> call_diversions{};
};

AccountParam loadAdvancedAccount(const std::string& json);

} // namespace flexisip::flexiapi