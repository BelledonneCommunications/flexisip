/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/events/sip-event-log.hh"

#include "sofia-sip/sip_protos.h"

namespace flexisip {

SipEventLog::SipEventLog(const sip_t& sip)
    : mFrom(::sip_from_dup(mHome.home(), sip.sip_from)), mTo(::sip_to_dup(mHome.home(), sip.sip_to)){};

} // namespace flexisip
