/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstddef>
#include <string>

#include "sofia-sip/sip.h"

namespace flexisip {

class EventId {
public:
	explicit EventId(const sip_t&);

	operator std::string() const {
		return std::to_string(mHash);
	}

private:
	std::size_t mHash;
};

} // namespace flexisip
