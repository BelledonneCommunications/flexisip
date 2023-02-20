/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
