/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "message-or-call-started.hh"

#include "eventlogs/events/identified.hh"
#include "fork-context/branch-info.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {
using namespace std;

MessageOrCallStarted::MessageOrCallStarted(const sip_t& sip,
                                           const std::list<std::shared_ptr<BranchInfo>>& branchInfoList)
    : SipEventLog(sip), Identified(sip) {
	mDevices.reserve(branchInfoList.size());
	for (const auto& branchInfo : branchInfoList) {
		mDevices.emplace_back(*branchInfo->mContact);
	}
}

} // namespace flexisip
