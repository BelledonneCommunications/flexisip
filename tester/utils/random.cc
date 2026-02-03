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

#include "random.hh"

#include <iostream>

namespace flexisip::tester {

namespace {

const auto sSeed = [] {
	auto seed = std::random_device{}();
	try {
		if (auto envVar = std::getenv("FLEXISEED")) seed = std::stoul(envVar, nullptr, 0 /* Autodect base */);
	} catch (const std::invalid_argument&) {
		// leave sSeed untouched
	} catch (const std::out_of_range&) {
		// leave sSeed untouched
	}
	std::cerr << "FLEXISEED=" << seed << "\n";
	return seed;
}();

} // namespace

namespace random {

std::random_device::result_type seed() {
	return sSeed;
}

std::default_random_engine engine() {
	return std::default_random_engine{seed()};
}

Random random() {
	return Random{seed()};
}

} // namespace random
} // namespace flexisip::tester