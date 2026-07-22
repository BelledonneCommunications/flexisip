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

#include "realm-json.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexiapi/schemas/optional-json.hh"
#include "flexiapi/schemas/schemas-json.hh"
#include "utils/load-file.hh"

using namespace std;

namespace flexisip::flexiapi {

void from_json(const nlohmann ::json& nlohmann_json_j, Bearer& nlohmann_json_t) {
	Bearer nlohmann_json_default_obj{};
	NLOHMANN_JSON_FROM(authz_server);
	NLOHMANN_JSON_FROM(audience);
	NLOHMANN_JSON_FROM(sip_id_claim);
	NLOHMANN_JSON_FROM_WITH_DEFAULT(public_key_type);
	NLOHMANN_JSON_FROM_WITH_DEFAULT(public_key_location);
}

void verifyBearerSchemaIntegrity(const nlohmann::json& config) {
	if (!config.is_object()) {
		throw nlohmann::json::type_error::create(302, "type must be object", &config);
	}

	// Required fields.
	for (const auto& fieldName : {"authz_server", "audience", "sip_id_claim"}) {
		if (!config.contains(fieldName)) {
			throw nlohmann::json::type_error::create(302, "missing required field '"s + fieldName + "'", &config);
		}
		const auto& field = config[fieldName];
		if (!field.is_string()) {
			throw nlohmann::json::type_error::create(302, "field '"s + fieldName + "' should be a string", &config);
		}
	}

	// Optional fields.
	for (const auto& fieldName : {"public_key_type", "public_key_location"}) {
		if (config.contains(fieldName) && !config[fieldName].is_string()) {
			throw nlohmann::json::type_error::create(302, "field '"s + fieldName + "' should be a string", &config);
		}
	}
}

void from_json(const nlohmann ::json& nlohmann_json_j, Realm& nlohmann_json_t) {
	if (nlohmann_json_j.is_string()) {
		const auto data = loadFromFile(nlohmann_json_j.get<string>());
		const auto json = nlohmann::json::parse(data);
		verifyRealmSchemaIntegrity(json);
		from_json(json, nlohmann_json_t);
	} else {
		Realm nlohmann_json_default_obj{};
		NLOHMANN_JSON_FROM(realm);
		NLOHMANN_JSON_FROM_WITH_DEFAULT(bearer);
	}
}

void verifyRealmSchemaIntegrity(const nlohmann::json& config) {
	if (!config.is_string() && !config.is_object()) {
		throw nlohmann::json::type_error::create(302, "type must be string or object", &config);
	}

	if (!config.contains("realm")) {
		throw nlohmann::json::type_error::create(302, "missing required field 'realm'", &config);
	}
	const auto& field = config["realm"];
	if (!field.is_string()) {
		throw nlohmann::json::type_error::create(302, "field 'realm' should be a string", &config);
	}

	if (config.contains("bearer")) {
		const auto& bearer = config["bearer"];
		if (!bearer.is_object()) {
			throw nlohmann::json::type_error::create(302, "field 'bearer' should be an object", &bearer);
		}

		verifyBearerSchemaIntegrity(bearer);
	}
}

} // namespace flexisip::flexiapi