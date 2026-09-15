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

#include "slot-creation-json.hh"

namespace flexisip::flexiapi {

void from_json(const nlohmann::json& nlohmann_json_j, SlotCreation& nlohmann_json_t) {
	SlotCreation nlohmann_json_default_obj{};
	NLOHMANN_JSON_FROM(sip_from);
	NLOHMANN_JSON_FROM(content_type);
}

void to_json(nlohmann::json& nlohmann_json_j, const SlotCreation& nlohmann_json_t) {
	nlohmann_json_j["sip_from"] = nlohmann_json_t.sip_from;
	nlohmann_json_j["content_type"] = nlohmann_json_t.content_type;
}

} // namespace flexisip::flexiapi