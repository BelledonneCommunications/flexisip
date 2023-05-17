/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "sofia-sip/sip.h"

#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "eventlogs/events/identified.hh"
#include "eventlogs/events/sip-event-log.hh"
#include "eventlogs/events/timestamped.hh"

namespace flexisip {

class BranchInfo;
struct ExtendedContact;

class CallStartedEventLog : public EventLogWriteDispatcher, public SipEventLog, public Identified, public Timestamped {
public:
	CallStartedEventLog(const sip_t&, const std::list<std::shared_ptr<BranchInfo>>&);

	std::vector<ExtendedContact> mDevices;

protected:
	void write(EventLogWriter& writer) const override;
};

} // namespace flexisip
