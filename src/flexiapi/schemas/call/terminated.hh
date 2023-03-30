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

#include <string>

#include "flexiapi/schemas/iso-8601-date.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

#pragma once

namespace flexisip {
namespace flexiapi {

enum class TerminatedState {
	ERROR,
	DECLINED,
	CANCELED,
	ACCEPTED_ELSEWHERE,
	DECLINED_ELSEWHERE,
	ACCEPTED,
};

NLOHMANN_JSON_SERIALIZE_ENUM(TerminatedState,
                             {
                                 {TerminatedState::ERROR, "error"},
                                 {TerminatedState::DECLINED, "declined"},
                                 {TerminatedState::CANCELED, "canceled"},
                                 {TerminatedState::ACCEPTED_ELSEWHERE, "accepted_elsewhere"},
                                 {TerminatedState::DECLINED_ELSEWHERE, "declined_elsewhere"},
                                 {TerminatedState::ACCEPTED, "accepted"},
                             })
class Terminated {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	Terminated() = default;
	Terminated(const ISO8601Date& at, const TerminatedState state) : at(at), state(state) {
	}
	NLOHMANN_DEFINE_TYPE_INTRUSIVE(Terminated, at, state)
private:
	ISO8601Date at{};
	TerminatedState state;
};

} // namespace flexiapi
} // namespace flexisip