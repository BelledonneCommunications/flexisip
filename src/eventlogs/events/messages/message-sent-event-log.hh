/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "eventlogs/events/message-or-call-started.hh"
#include "eventlogs/events/messages/with-message-kind.hh"
#include "fork-context/message-kind.hh"

namespace flexisip {

// Note that as the proxy has no notion of group chats, this event can only have one destination (which would be the
// chatroom in case of a group message)
class MessageSentEventLog : public MessageOrCallStarted, public WithMessageKind {
public:
	MessageSentEventLog(const sip_t&, const std::list<std::shared_ptr<BranchInfo>>&, const MessageKind&);

protected:
	void write(EventLogWriter& writer) const override;
};

} // namespace flexisip
