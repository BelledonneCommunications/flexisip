/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "event-log-writer.hh"

#include "eventlogs/events/messages/message-response-from-recipient-event-log.hh"

namespace flexisip {

void EventLogWriter::write(const MessageResponseFromRecipientEventLog& event) {
	write(static_cast<const MessageLog&>(event));
}

} // namespace flexisip
