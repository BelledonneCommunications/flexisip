/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/message-or-call-started.hh"

namespace flexisip {

class CallStartedEventLog : public MessageOrCallStarted, public WithInviteKind {
public:
	CallStartedEventLog(const sip_t&, const std::list<std::shared_ptr<BranchInfo>>&);

protected:
	void write(EventLogWriter& writer) const override;
};

} // namespace flexisip
