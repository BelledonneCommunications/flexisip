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

#include "flexisip/utils/sip-uri.hh"

namespace flexisip::flexiapi {

class ApiFormattedUri {
public:
	struct JsonHandler;

	ApiFormattedUri(const url_t& url) {
		std::ostringstream concatenated{};
		concatenated << url.url_user << "@" << url.url_host;
		apiFormattedUri = concatenated.str();
	}
	ApiFormattedUri(const SipUri& sipUri) : ApiFormattedUri(*sipUri.get()) {}

	operator std::string_view() const {
		return apiFormattedUri;
	}
	operator std::string() const& {
		return apiFormattedUri;
	}
	operator std::string() && {
		return std::move(apiFormattedUri);
	}

	bool operator==(const ApiFormattedUri& other) const = default;

private:
	friend std::hash<ApiFormattedUri>;

	std::string apiFormattedUri;
};

} // namespace flexisip::flexiapi

namespace std {
template <>
struct hash<flexisip::flexiapi::ApiFormattedUri> {
	size_t operator()(const flexisip::flexiapi::ApiFormattedUri& apiUri) const noexcept {
		return hash<string>()(apiUri.apiFormattedUri);
	}
};
} // namespace std