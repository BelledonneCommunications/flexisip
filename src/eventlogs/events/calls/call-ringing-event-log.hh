/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "sofia-sip/sip.h"

#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "eventlogs/events/identified.hh"
#include "eventlogs/events/timestamped.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {

class BranchInfo;

class CallRingingEventLog : public EventLogWriteDispatcher, public Identified, public Timestamped {
public:
	CallRingingEventLog(const sip_t&, const BranchInfo*);

	const ExtendedContact& getDevice() const {
		return mDevice;
	}

protected:
	void write(EventLogWriter& writer) const override;

	const ExtendedContact mDevice;
};

} // namespace flexisip
