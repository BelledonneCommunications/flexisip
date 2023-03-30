/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <optional>
#include <string>

#include "flexiapi/schemas/iso-8601-date.hh"
#include "flexiapi/schemas/optional-json.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

#pragma once

namespace flexisip {
namespace flexiapi {

enum class ParticipantEventType {
	ADDED,
	LEFT,
	REMOVED,
};

NLOHMANN_JSON_SERIALIZE_ENUM(ParticipantEventType,
                             {
                                 {ParticipantEventType::ADDED, "added"},
                                 {ParticipantEventType::LEFT, "left"},
                                 {ParticipantEventType::REMOVED, "removed"},
                             })

class ParticipantEvent {
public:
	ParticipantEvent(ParticipantEventType type, const ISO8601Date& at) : type(type), at(at) {
	}
	NLOHMANN_DEFINE_TYPE_INTRUSIVE(ParticipantEvent, type, at);

private:
	ParticipantEventType type;
	ISO8601Date at;
};

} // namespace flexiapi
} // namespace flexisip