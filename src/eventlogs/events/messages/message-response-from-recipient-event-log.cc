/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "message-response-from-recipient-event-log.hh"

#include "eventlogs/events/event-id.hh"
#include "eventlogs/events/identified.hh"
#include "eventlogs/events/messages/with-message-kind.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/message-kind.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {
using namespace std;

MessageResponseFromRecipientEventLog::MessageResponseFromRecipientEventLog(const sip_t& sip,
                                                                           const ExtendedContact& device,
                                                                           const MessageKind& kind,
                                                                           std::optional<EventId> id)
    : MessageLog(sip), Identified(id ? *id : EventId(sip)), WithMessageKind(kind),
      mDevice(device) {
}

MessageResponseFromRecipientEventLog::ReportType MessageResponseFromRecipientEventLog::getReportType() const {
	return ReportType::ResponseFromRecipient;
}

void MessageResponseFromRecipientEventLog::write(EventLogWriter& writer) const {
	writer.write(*this);
}

} // namespace flexisip
