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

#include "flexiapi/schemas/iso-8601-date.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"

#undef sip_from

namespace flexisip::flexiapi {

class Slot {
public:
	// Do not use default constructor, here only for nlohmann json serialization.
	Slot() = default;
	Slot(const std::string& id,
	     const std::string& sip_from,
	     const std::string& upload_url,
	     const int& max_upload_size,
	     const std::string& content_type)
	    : id(id), sip_from(sip_from), upload_url(upload_url), max_upload_size(max_upload_size),
	      content_type(content_type) {}

	NLOHMANN_DEFINE_TYPE_INTRUSIVE(Slot, id, sip_from, upload_url, max_upload_size, content_type);

	std::string getUploadUrl() const {
		return upload_url;
	}
	int getMaxUploadSize() const {
		return max_upload_size;
	}

private:
	std::string id{};
	std::string sip_from{};
	std::string upload_url{};
	int max_upload_size{};
	std::string content_type{};
};

} // namespace flexisip::flexiapi
