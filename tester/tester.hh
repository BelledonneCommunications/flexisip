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

#include <cstddef>
#include <filesystem>
#include <random>
#include <string>

#include "utils/rand.hh"

namespace flexisip::tester {

std::string bcTesterFile(const std::string& name);
std::string bcTesterRes(const std::string& name);
// Canonical path to the configured writable directory for flexisip_tester
std::filesystem::path bcTesterWriteDir();

void flexisip_tester_add_grammar_loader_path(const std::string& path);
void flexisip_tester_set_factory_resources_path(const std::string& path);
void flexisip_tester_init();
void flexisip_tester_uninit();

namespace random {

/**
 * Get seed for the currently running instance.
 * @return seed
 */
std::random_device::result_type seed();

/**
 * Get default random engine initialized with the seed of the currently running instance.
 * @return default random engine
 */
[[deprecated("Use random() instead")]] std::default_random_engine engine();

/**
 * Creates a 'Random' instance seeded with random::seed().
 */
Random random();

} // namespace random
} // namespace flexisip::tester