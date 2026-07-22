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

#include "space-json.hh"

#include <string>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexiapi/schemas/optional-json.hh"
#include "realm-json.hh"

using namespace std;

namespace flexisip::flexiapi {

void from_json(const nlohmann ::json& nlohmann_json_j, Space& nlohmann_json_t) {
	Space nlohmann_json_default_obj{};
	NLOHMANN_JSON_FROM(name);
	NLOHMANN_JSON_FROM(domain);
	NLOHMANN_JSON_FROM_WITH_DEFAULT(realm);
	NLOHMANN_JSON_FROM_WITH_DEFAULT(accounts);
}

void verifySpacesSchemaIntegrity(const nlohmann::json& config) {
	if (!config.is_array()) {
		throw nlohmann::json::type_error::create(302, "type must be array", &config);
	}

	vector<string> domains{};
	for (const auto& space : config) {
		if (!space.is_object()) {
			throw nlohmann::json::type_error::create(302, "type must be object", &space);
		}

		if (!space.contains("name")) {
			throw nlohmann::json::out_of_range::create(403, "field 'name' is missing", &space);
		}
		if (!space["name"].is_string()) {
			throw nlohmann::json::type_error::create(302, "field 'name' must be a string", &space);
		}

		if (!space.contains("domain")) {
			throw nlohmann::json::out_of_range::create(403, "field 'domain' is missing", &space);
		}
		if (!space["domain"].is_string()) {
			throw nlohmann::json::type_error::create(302, "field 'domain' must be a string", &space);
		}

		const string& domain = space["domain"];
		if (find(domains.begin(), domains.end(), domain) != domains.end()) {
			throw nlohmann::json::other_error::create(500, "duplicate field 'domain' found: " + domain, &space);
		} else {
			domains.push_back(domain);
		}

		if (space.contains("accounts") && !space["accounts"].is_string()) {
			throw nlohmann::json::type_error::create(302, "field 'accounts' must be a string", &space);
		}

		if (space.contains("realm")) {
			verifyRealmSchemaIntegrity(space["realm"]);
		}
	}
}

} // namespace flexisip::flexiapi
