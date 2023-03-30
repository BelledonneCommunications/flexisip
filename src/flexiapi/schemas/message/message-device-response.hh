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

class MessageDeviceResponse {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	MessageDeviceResponse() = default;
	MessageDeviceResponse(int lastStatus, const ISO8601Date& receivedAt)
	    : last_status(lastStatus), received_at(receivedAt) {
	}
	NLOHMANN_DEFINE_TYPE_INTRUSIVE(MessageDeviceResponse, last_status, received_at)

private:
	int last_status = 0;
	ISO8601Date received_at{};
};

} // namespace flexiapi
} // namespace flexisip
