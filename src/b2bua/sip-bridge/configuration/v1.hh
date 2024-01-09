/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
    In-memory representation of a Provider configuration file
*/

#pragma once

#include <string>
#include <vector>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "media-encryption.hh"

#include "flexiapi/schemas/optional-json.hh"

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
