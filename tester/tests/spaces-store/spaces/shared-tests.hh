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

#include <array>
#include <string>
#include <vector>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexiapi/schemas/space/space.hh"

namespace flexisip::tester {

static const std::array<std::string, 2> kTestDomains{
    "example.org",
    "other.example.org",
};
static const std::vector<flexiapi::Space> kTestSpaces{
    {.name = "space-1", .domain = kTestDomains[0]},
    {.name = "space-2", .domain = kTestDomains[1]},
};
const nlohmann::json kTestSpacesJson = {
    {
        {"name", kTestSpaces[0].name},
        {"domain", kTestSpaces[0].domain},
        {"super", true},
    },
    {
        {"name", kTestSpaces[1].name},
        {"domain", kTestSpaces[1].domain},
        {"super", false},
    },
};

void hasSpaces(const std::vector<flexiapi::Space>& value, const std::vector<flexiapi::Space>& expected);

} // namespace flexisip::tester