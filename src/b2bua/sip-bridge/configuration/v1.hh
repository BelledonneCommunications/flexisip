/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

/*
    In-memory representation of a Provider configuration file
*/

#pragma once

#include <string>
#include <vector>

#include "flexiapi/schemas/optional-json.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

namespace flexisip::b2bua::bridge::config::v1 {

struct AccountDesc {
	std::string uri = "";
	std::string userid = "";
	std::string password = "";
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(AccountDesc, uri, userid, password);

struct ProviderDesc {
	std::string name = "";
	std::string pattern = "";
	std::string outboundProxy = "";
	bool registrationRequired = false;
	uint32_t maxCallsPerLine = std::numeric_limits<std::uint32_t>::max();
	std::vector<AccountDesc> accounts = {};
	std::optional<bool> enableAvpf = std::nullopt;
	std::optional<linphone::MediaEncryption> mediaEncryption = std::nullopt;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ProviderDesc,
                                                name,
                                                pattern,
                                                outboundProxy,
                                                registrationRequired,
                                                maxCallsPerLine,
                                                accounts,
                                                enableAvpf,
                                                mediaEncryption);

using Root = std::vector<ProviderDesc>;

} // namespace flexisip::b2bua::bridge::config::v1