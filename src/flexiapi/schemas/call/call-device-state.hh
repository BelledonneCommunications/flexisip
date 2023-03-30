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
#include "terminated.hh"

#pragma once

namespace flexisip {
namespace flexiapi {

class CallDeviceState {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	CallDeviceState() = default;
	CallDeviceState(const std::optional<ISO8601Date>& rangAt, const std::optional<Terminated>& inviteTerminated)
	    : rang_at(rangAt), invite_terminated(inviteTerminated) {
	}
	CallDeviceState(const ISO8601Date& rangAt) : rang_at(rangAt), invite_terminated(std::nullopt) {
	}
	CallDeviceState(const Terminated& inviteTerminated) : rang_at(std::nullopt), invite_terminated(inviteTerminated) {
	}

	friend void to_json(nlohmann::json& j, const CallDeviceState& callDeviceState) {
		if (callDeviceState.rang_at) {
			j["rang_at"] = callDeviceState.rang_at;
		}
		if (callDeviceState.invite_terminated) {
			j["invite_terminated"] = callDeviceState.invite_terminated;
		}
		if (j.is_null()) {
			j = nlohmann::json::value_t::object;
		}
	};
	friend void from_json(const nlohmann::json& j, CallDeviceState& callDeviceState) {
		j.at("rang_at").get_to(callDeviceState.rang_at);
		j.at("invite_terminated").get_to(callDeviceState.invite_terminated);
	};

private:
	std::optional<ISO8601Date> rang_at{};
	std::optional<Terminated> invite_terminated = std::nullopt;
};

} // namespace flexiapi
} // namespace flexisip