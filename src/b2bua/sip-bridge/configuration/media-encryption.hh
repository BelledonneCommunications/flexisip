/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
    In-memory representation of a Provider configuration file
*/

#pragma once

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "linphone++/enums.hh" // IWYU pragma: export

#include "utils/string-utils.hh"

NLOHMANN_JSON_NAMESPACE_BEGIN
template <>
struct adl_serializer<linphone::MediaEncryption> {
	static void to_json(json&, const linphone::MediaEncryption&) {
		throw std::runtime_error{"unimplemented"};
	}

	static void from_json(const json& j, linphone::MediaEncryption& encryption) {
		encryption = *StringUtils::string2MediaEncryption(j.get<std::string>());
	}
};
NLOHMANN_JSON_NAMESPACE_END
