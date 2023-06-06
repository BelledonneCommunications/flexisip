/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "call-started-event-log.hh"

#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/message-or-call-started.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {
using namespace std;

CallStartedEventLog::CallStartedEventLog(const sip_t& sip,
                                         const std::list<std::shared_ptr<BranchInfo>>& branchInfoList)
    : MessageOrCallStarted(sip, branchInfoList), WithInviteKind(*sip.sip_content_type) {
}

void CallStartedEventLog::write(EventLogWriter& writer) const {
	writer.write(*this);
}

} // namespace flexisip
