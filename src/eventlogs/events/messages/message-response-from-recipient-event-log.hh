/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <optional>

#include "eventlogs/events/event-id.hh"
#include "fork-context/message-kind.hh"
#include "sofia-sip/sip.h"

#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/events/identified.hh"
#include "eventlogs/events/messages/with-message-kind.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {

class MessageResponseFromRecipientEventLog : public MessageLog,
                                             public Identified,
                                             public WithMessageKind {
public:
	MessageResponseFromRecipientEventLog(const sip_t&,
	                                     const ExtendedContact&,
	                                     const MessageKind&,
	                                     std::optional<EventId> id = std::nullopt);

	ReportType getReportType() const override;
	const ExtendedContact& getDevice() const {
		return mDevice;
	}

protected:
	void write(EventLogWriter& writer) const override;

	const ExtendedContact mDevice;
};

} // namespace flexisip
