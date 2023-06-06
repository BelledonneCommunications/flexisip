/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "sofia-sip/sip.h"

#include "eventlogs/events/event-id.hh"

namespace flexisip {

class Identified {
public:
	explicit Identified(const sip_t& sip) : mId(sip) {
	}
	explicit Identified(const EventId& sip) : mId(sip) {
	}

	const EventId& getId() const {
		return mId;
	}

private:
	const EventId mId;
};

} // namespace flexisip
