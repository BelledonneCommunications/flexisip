/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
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

class MessageResponseFromRecipientEventLog : public MessageLog, public Identified, public WithMessageKind {
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