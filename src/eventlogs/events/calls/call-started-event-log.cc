/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/events/calls/call-started-event-log.hh"

#include <type_traits>
#include <vector>

#include "eventlogs/events/identified.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/branch-info.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {
using namespace std;

CallStartedEventLog::CallStartedEventLog(const sip_t& sip, const std::list<std::shared_ptr<BranchInfo>>& branchInfoList)
    : SipEventLog(sip), Identified(sip) {
	mDevices.reserve(branchInfoList.size());
	for (const auto& branchInfo : branchInfoList) {
		mDevices.emplace_back(*branchInfo->mContact);
	}
}

void CallStartedEventLog::write(EventLogWriter& writer) const {
	writer.write(*this);
}

} // namespace flexisip
