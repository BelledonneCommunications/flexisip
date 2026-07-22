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

#include <filesystem>
#include <optional>
#include <string>

#include "auth/bearer-auth.hh"
#include "flexisip/sofia-wrapper/url.hh"

namespace flexisip::flexiapi {

struct Bearer {
	sofiasip::Url authz_server{};
	std::string audience{};
	std::string sip_id_claim{};
	std::optional<flexisip::Bearer::PubKeyType> public_key_type{flexisip::Bearer::PubKeyType::wellKnown};
	std::optional<std::filesystem::path> public_key_location{std::nullopt};
};

struct Realm {
	std::string realm{};
	std::optional<Bearer> bearer{std::nullopt};
};

} // namespace flexisip::flexiapi
