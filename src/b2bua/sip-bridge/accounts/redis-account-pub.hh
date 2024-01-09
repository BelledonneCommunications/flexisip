/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexisip/utils/sip-uri.hh"

namespace flexisip::b2bua::bridge {

class RedisAccountPub {
public:
	SipUri uri;
	std::string identifier;
};

inline void from_json(const nlohmann::json& j, RedisAccountPub& r) {
	std::string username{};
	std::string domain{};
	j.at("username").get_to(username);
	j.at("domain").get_to(domain);
	r.uri = SipUri{"sip:" + username + "@" + domain};

	j.at("identifier").get_to(r.identifier);
}

} // namespace flexisip::b2bua::bridge