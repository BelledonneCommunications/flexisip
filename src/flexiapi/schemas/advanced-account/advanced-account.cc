
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

#include "advanced-account.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

using namespace nlohmann;
using namespace nlohmann::literals;

namespace flexisip {

inline void to_json(json& j, const flexisip::SipUri& uri) {
	j = uri.str();
}

inline void from_json(const json& j, flexisip::SipUri& uri) {
	uri = SipUri(j.get<std::string>());
}

namespace flexiapi {
NLOHMANN_JSON_SERIALIZE_ENUM(UriType,
                             {
                                 {UriType::Account, "account"},
                                 {UriType::Group, "group"},
                             })

NLOHMANN_JSON_SERIALIZE_ENUM(CallDiversion::Type,
                             {
                                 {CallDiversion::Type::Always, "always"},
                                 {CallDiversion::Type::Busy, "busy"},
                                 {CallDiversion::Type::Away, "away"},
                             })

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(CallDiversion, type, target, target_type)

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(AccountParam, sip_uri, call_diversions)

AccountParam loadAdvancedAccount(const std::string& json) {
	auto jsonData = json::parse(json);
	AccountParam p;
	jsonData.at("payload").get_to(p);
	return p;
}
} // namespace flexiapi
} // namespace flexisip