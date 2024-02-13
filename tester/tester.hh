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

#include <cstddef>
#include <filesystem>
#include <random>
#include <string>

namespace flexisip {
namespace tester {

std::string bcTesterFile(const std::string& name);
std::string bcTesterRes(const std::string& name);
// Canonical path to the configured writable directory for flexisip_tester
std::filesystem::path bcTesterWriteDir();

void flexisip_tester_init();
void flexisip_tester_uninit();

std::random_device::result_type seed();
std::default_random_engine randomEngine();
std::string randomString(std::size_t);

} // namespace tester
} // namespace flexisip
