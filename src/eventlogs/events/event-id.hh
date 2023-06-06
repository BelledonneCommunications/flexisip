/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include "sofia-sip/sip.h"

namespace flexisip {

class EventId {
public:
	explicit EventId(const sip_t&);
	// Parse an ID serialized to a string. May throw the same exceptions as std::stoull.
	explicit EventId(const std::string&);

	operator std::string() const {
		return std::to_string(mHash);
	}

private:
	const std::size_t mHash;
};

} // namespace flexisip
