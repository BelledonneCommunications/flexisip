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

#include "flexiapi/schemas/account/account.hh"
#include "flexiapi/schemas/account/call-forwarding.hh"
#include "flexiapi/schemas/account/group.hh"
#include "flexiapi/schemas/account/resolved-uri.hh"
#include "flexiapi/schemas/account/uri-type.hh"
#include "flexiapi/schemas/schemas-json.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

namespace flexisip::flexiapi {

struct ResolvedUri::JsonDeserializer {
	static void fromJson(const nlohmann::json& j, ResolvedUri& r);
};

void from_json(const nlohmann::json& j, Account& a);
void to_json(nlohmann::json& j, Account& a);

void from_json(const nlohmann::json& j, CallForwarding& c);
NLOHMANN_JSON_SERIALIZE_ENUM(CallForwarding::Type,
                             {
                                 {CallForwarding::Type::Always, toString(CallForwarding::Type::Always)},
                                 {CallForwarding::Type::Away, toString(CallForwarding::Type::Away)},
                                 {CallForwarding::Type::Busy, toString(CallForwarding::Type::Busy)},
                             })

NLOHMANN_JSON_SERIALIZE_ENUM(CallForwarding::ForwardType,
                             {
                                 {CallForwarding::ForwardType::Contact, toString(CallForwarding::ForwardType::Contact)},
                                 {CallForwarding::ForwardType::SipUri, toString(CallForwarding::ForwardType::SipUri)},
                                 {CallForwarding::ForwardType::Voicemail,
                                  toString(CallForwarding::ForwardType::Voicemail)},
                             })

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Group, sip_uri)

NLOHMANN_JSON_SERIALIZE_ENUM(UriType,
                             {
                                 {UriType::Account, toString(UriType::Account)},
                                 {UriType::Group, toString(UriType::Group)},
                                 {UriType::Unknown, toString(UriType::Unknown)},
                             })
} // namespace flexisip::flexiapi

NLOHMANN_JSON_NAMESPACE_BEGIN
template <>
struct adl_serializer<flexisip::flexiapi::ResolvedUri> {
	static void from_json(const json& j, flexisip::flexiapi::ResolvedUri& r) {
		flexisip::flexiapi::ResolvedUri::JsonDeserializer::fromJson(j, r);
	}
};
NLOHMANN_JSON_NAMESPACE_END
