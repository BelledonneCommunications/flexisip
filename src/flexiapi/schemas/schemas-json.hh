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

#include "flexiapi/schemas/api-formatted-uri.hh"
#include "flexisip/utils/sip-uri.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

namespace flexisip {

inline void to_json(nlohmann::json& j, const SipUri& uri) {
	j = uri.str();
}

inline void from_json(const nlohmann::json& j, SipUri& uri) {
	uri = SipUri(j.get<std::string>());
}
} // namespace flexisip

namespace flexisip::flexiapi {
struct ApiFormattedUri::JsonHandler {
	static void fromJson(const nlohmann::json& j, ApiFormattedUri& a);
	static void toJson(nlohmann::json& j, const ApiFormattedUri& a);
};
} // namespace flexisip::flexiapi

NLOHMANN_JSON_NAMESPACE_BEGIN
template <>
struct adl_serializer<flexisip::flexiapi::ApiFormattedUri> {
	static void from_json(const json& j, flexisip::flexiapi::ApiFormattedUri& a) {
		flexisip::flexiapi::ApiFormattedUri::JsonHandler::fromJson(j, a);
	}
	static void to_json(json& j, const flexisip::flexiapi::ApiFormattedUri& a) {
		flexisip::flexiapi::ApiFormattedUri::JsonHandler::toJson(j, a);
	}
};
NLOHMANN_JSON_NAMESPACE_END