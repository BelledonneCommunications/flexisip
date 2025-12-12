/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include <string>

#include "lib/nlohmann-json-3-11-2/json.hpp"

#undef sip_from

namespace flexisip::flexiapi {

class SlotCreation {

public:
	SlotCreation() = default;
	SlotCreation(const std::string& sip_from, const std::string& content_type)
	    : sip_from(sip_from), content_type(content_type) {}

	NLOHMANN_DEFINE_TYPE_INTRUSIVE(SlotCreation, sip_from, content_type);

private:
	// SIP URI of the caller
	std::string sip_from{};
	// Content type of the audio file to upload (`audio/opus` or `audio/wav`)
	std::string content_type{};
};

} // namespace flexisip::flexiapi
