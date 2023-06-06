/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "message-sent-event-log.hh"

#include "eventlogs/events/message-or-call-started.hh"
#include "eventlogs/events/messages/with-message-kind.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/message-kind.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {

MessageSentEventLog::MessageSentEventLog(const sip_t& sip,
                                         const std::list<std::shared_ptr<BranchInfo>>& branchInfoList,
                                         const MessageKind& kind)
    : MessageOrCallStarted(sip, branchInfoList), WithMessageKind(kind) {
}

void MessageSentEventLog::write(EventLogWriter& writer) const {
	writer.write(*this);
}

} // namespace flexisip
