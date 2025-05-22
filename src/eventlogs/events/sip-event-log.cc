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

#include "eventlogs/events/sip-event-log.hh"

#include "sofia-sip/sip_protos.h"

namespace flexisip {

SipEventLog::SipEventLog(const sip_t& sip)
    : mFrom(::sip_from_dup(mHome.home(), sip.sip_from)), mTo(::sip_to_dup(mHome.home(), sip.sip_to)),
      mCallId(::sip_call_id_dup(mHome.home(), sip.sip_call_id)) {};

} // namespace flexisip