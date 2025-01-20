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

#include "call-started-event-log.hh"

#include "eventlogs/events/calls/invite-kind.hh"
#include "eventlogs/events/message-or-call-started.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {
using namespace std;

CallStartedEventLog::CallStartedEventLog(const sip_t& sip, const std::list<std::shared_ptr<BranchInfo>>& branchInfoList)
    : MessageOrCallStarted(sip, branchInfoList), WithInviteKind(sip.sip_content_type) {
}

void CallStartedEventLog::write(EventLogWriter& writer) const {
	writer.write(*this);
}

} // namespace flexisip