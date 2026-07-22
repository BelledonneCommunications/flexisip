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

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "auth/bearer-auth.hh"
#include "realm.hh"

namespace flexisip {

NLOHMANN_JSON_SERIALIZE_ENUM(Bearer::PubKeyType,
                             {
                                 {Bearer::PubKeyType::file, "file"},
                                 {Bearer::PubKeyType::wellKnown, "well-known"},
                             })

namespace flexiapi {

void from_json(const nlohmann ::json& nlohmann_json_j, Bearer& nlohmann_json_t);

/**
 * @throws nlohmann::json::exception if the json schema is invalid
 */
void verifyBearerSchemaIntegrity(const nlohmann::json& config);

void from_json(const nlohmann ::json& nlohmann_json_j, Realm& nlohmann_json_t);

/**
 * @throws nlohmann::json::exception if the json schema is invalid
 */
void verifyRealmSchemaIntegrity(const nlohmann::json& config);

} // namespace flexiapi

} // namespace flexisip