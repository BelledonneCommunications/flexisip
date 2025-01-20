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

#include "sofia-sip/sip.h"

#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "eventlogs/events/identified.hh"
#include "eventlogs/events/timestamped.hh"

namespace flexisip {

class BranchInfo;

class CallEndedEventLog : public EventLogWriteDispatcher, public Identified, public Timestamped {
public:
	CallEndedEventLog(const sip_t&);

protected:
	void write(EventLogWriter& writer) const override;
};

} // namespace flexisip