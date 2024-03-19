/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <fstream>
#include <string>
#include <string_view>

#include "flexisip/logmanager.hh"

namespace flexisip {
static std::string loadFromFile(std::string_view path) {
	std::ifstream ifs(path.data());
	if (!ifs.is_open()) {
		LOGF("Failed to open file: %s", path.data());
	}
	std::stringstream sstr;
	sstr << ifs.rdbuf();

	if (sstr.bad() || sstr.fail()) {
		LOGF("Failed to read from file '%s'", path.data());
	}
	return sstr.str();
}
} // namespace flexisip