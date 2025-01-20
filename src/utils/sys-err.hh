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

#include <cerrno>
#include <ostream>
#include <type_traits>

namespace flexisip {

/**
 * Encapsulates the error returned by a C library function call, as read from errno.
 *
 * The constructor immediately reads and stores the value of errno in the new instance and is therefore expected to be
 * called immediately after detecting an erroneous return from a library call.
 *
 * That value can then be retrieved via the number() method.
 */
class SysErr {
public:
	SysErr() : err(errno) {
	}

	// Returns the captured errno value
	auto number() const {
		return err;
	}

private:
	std::decay_t<decltype(errno)> err;
};

std::ostream& operator<<(std::ostream&, const SysErr&) noexcept;

} // namespace flexisip