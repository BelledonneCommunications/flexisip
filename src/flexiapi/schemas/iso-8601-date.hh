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

#include <chrono>
#include <ctime>
#include <iomanip>
#include <ostream>
#include <sstream>

#include "flexisip/logmanager.hh"

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "eventlogs/events/timestamped.hh"

namespace flexisip {
namespace flexiapi {

class ISO8601Date {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	ISO8601Date() = default;
	ISO8601Date(const std::time_t& t) : mTimestamp(t) {
	}
	ISO8601Date(const Timestamp& t) : ISO8601Date(std::chrono::system_clock::to_time_t(t)) {
	}

	friend void to_json(nlohmann::json& j, const ISO8601Date& date) {
		std::ostringstream ss{};
		ss << date;
		j = ss.str();
	};
	friend void from_json(const nlohmann::json& j, ISO8601Date& date) {
		std::istringstream ss(j.get<std::string>());
		ss >> date;
		if (ss.fail())
			throw nlohmann::json::type_error::create(302, "Not a valid ISO-8601 UTC DateTime: " + ss.str(), &j);
	}

	friend std::ostream& operator<<(std::ostream& stream, const ISO8601Date& date) {
		return stream << std::put_time(::gmtime(&date.mTimestamp), kFormatString);
	}
	friend std::istream& operator>>(std::istream& stream, ISO8601Date& date) {
		std::tm t{};
		stream >> std::get_time(&t, kFormatString);
		if (!stream.fail()) date.mTimestamp = ::timegm(&t);

		return stream;
	}
	friend bool operator<=(const ISO8601Date& lhs, const ISO8601Date& rhs) {
		return lhs.mTimestamp <= rhs.mTimestamp;
	}
	friend bool operator<(const ISO8601Date& lhs, const ISO8601Date& rhs) {
		return lhs.mTimestamp < rhs.mTimestamp;
	}
	friend bool operator==(const ISO8601Date& lhs, const ISO8601Date& rhs) {
		return lhs.mTimestamp == rhs.mTimestamp;
	}

private:
	static constexpr auto kFormatString = "%Y-%m-%dT%H:%M:%SZ";

	std::time_t mTimestamp;
};
} // namespace flexiapi
} // namespace flexisip