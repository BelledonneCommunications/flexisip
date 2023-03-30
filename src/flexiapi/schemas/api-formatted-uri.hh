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

namespace flexisip {
namespace flexiapi {

class ApiFormattedUri {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	ApiFormattedUri();
	ApiFormattedUri(const url_t& url) {
		std::ostringstream concatenated{};
		concatenated << url.url_user << "@" << url.url_host;
		apiFormattedUri = concatenated.str();
	}

	operator std::string_view() const {
		return apiFormattedUri;
	};

	friend void to_json(nlohmann::json& j, const ApiFormattedUri& date) {
		j = date.apiFormattedUri;
	};
	friend void from_json(const nlohmann::json& j, ApiFormattedUri& date) {
		SLOGE << "ApiFormattedUri::apiFormattedUri used, this function is not safe (no checks)";
		date.apiFormattedUri = j.get<std::string>();
	}

	bool operator==(const ApiFormattedUri& other) const {
		return apiFormattedUri == other.apiFormattedUri;
	}

private:
	friend std::hash<flexisip::flexiapi::ApiFormattedUri>;

	std::string apiFormattedUri;
};

} // namespace flexiapi
} // namespace flexisip

namespace std {
template <>
struct hash<flexisip::flexiapi::ApiFormattedUri> {
	size_t operator()(const flexisip::flexiapi::ApiFormattedUri& apiUri) const {
		return hash<string>()(apiUri.apiFormattedUri);
	}
};
} // namespace std