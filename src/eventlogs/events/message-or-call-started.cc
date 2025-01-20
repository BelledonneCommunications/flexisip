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