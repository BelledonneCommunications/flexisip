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

#include "bc-utils.hh"

#include "bctoolbox/tester.h"

namespace flexisip::tester {

std::string bcTesterFile(const std::string& name) {
	char* file = bc_tester_file(name.c_str());
	std::string ret(file);
	bc_free(file);
	return ret;
}

std::string bcTesterRes(const std::string& name) {
	char* file = bc_tester_res(name.c_str());
	std::string ret(file);
	bc_free(file);
	return ret;
}

std::filesystem::path bcTesterWriteDir() {
	return std::filesystem::canonical(bc_tester_get_writable_dir_prefix());
}

std::filesystem::path bcTesterResourceDir() {
	return std::filesystem::canonical(bc_tester_get_resource_dir_prefix());
}

} // namespace flexisip::tester