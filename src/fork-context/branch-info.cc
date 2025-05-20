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

#include "branch-info.hh"

namespace flexisip {

std::shared_ptr<BranchInfo> BranchInfo::getBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr) {
	return tr ? tr->getProperty<BranchInfo>("BranchInfo") : nullptr;
}

void BranchInfo::setBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr, const std::weak_ptr<BranchInfo>& br) {
	if (tr) tr->setProperty("BranchInfo", br);
}

void BranchInfo::notifyBranchCanceled(ForkStatus cancelReason) noexcept {
	if (auto listener = mListener.lock()) listener->onBranchCanceled(shared_from_this(), cancelReason);
}

void BranchInfo::notifyBranchCompleted() noexcept {
	if (auto listener = mListener.lock()) listener->onBranchCompleted(shared_from_this());
}

int BranchInfo::getStatus() {
	return mLastResponse ? mLastResponse->getSip()->sip_status->st_status : 0;
}

bool BranchInfo::needsDelivery(FinalStatusMode mode) {
	auto currentStatus = getStatus();

	switch (mode) {
		case FinalStatusMode::ForkLate:
			return currentStatus < 200 || currentStatus == 503 || currentStatus == 408;
		case FinalStatusMode::RFC:
		default:
			return currentStatus < 200;
	}
}

BranchInfoDb BranchInfo::getDbObject() {
	std::string request{mRequestMsg->msgAsString()};
	std::string lastResponse{mLastResponse->msgAsString()};
	BranchInfoDb branchInfoDb{mUid, mPriority, request, lastResponse, mClearedCount};
	return branchInfoDb;
}

std::unique_ptr<RequestSipEvent>&& BranchInfo::extractRequest() {
	return std::move(mRequestEvent);
}

void BranchInfo::setRequest(std::unique_ptr<RequestSipEvent>&& req) {
	mRequestEvent = std::move(req);
}

} // namespace flexisip