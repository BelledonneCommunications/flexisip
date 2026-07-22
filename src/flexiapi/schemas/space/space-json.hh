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

#include "space.hh"

namespace flexisip::flexiapi {

void from_json(const nlohmann ::json& nlohmann_json_j, Space& nlohmann_json_t);

/**
 * @throws nlohmann::json::exception if the json schema is invalid
 */
void verifySpacesSchemaIntegrity(const nlohmann::json& config);

} // namespace flexisip::flexiapi