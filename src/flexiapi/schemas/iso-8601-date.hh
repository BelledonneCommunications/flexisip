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
#pragma once

#include "flexisip/logmanager.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "eventlogs/events/timestamped.hh"

namespace flexisip {
namespace flexiapi {

class ISO8601Date {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	ISO8601Date() = default;
	ISO8601Date(const time_t& t) : isoFormattedDate("1993-06-19T10:10:09Z") {
		strftime(isoFormattedDate.data(), isoFormattedDate.size() + 1, "%FT%TZ", gmtime(&t)), isoFormattedDate.size();
	}
	ISO8601Date(const Timestamp& t) : ISO8601Date(std::chrono::system_clock::to_time_t(t)) {
	}

	friend void to_json(nlohmann::json& j, const ISO8601Date& date) {
		j = date.isoFormattedDate;
	};
	friend void from_json(const nlohmann::json& j, ISO8601Date& date) {
		SLOGE << "ISO8601Date::from_json used, this function is not safe (no checks)";
		date.isoFormattedDate = j.get<std::string>();
	}

private:
	std::string isoFormattedDate;
};
} // namespace flexiapi
} // namespace flexisip