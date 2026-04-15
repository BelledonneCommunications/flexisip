/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "basic-fork-strategy.hh"

using namespace std;

namespace flexisip {

BasicForkStrategy::BasicForkStrategy() {
	mLogPrefix = LogManager::makeLogPrefixForInstance(this, "BasicForkStrategy");
	LOGD << "New instance";
}

BasicForkStrategy::~BasicForkStrategy() {
	LOGD << "Destroy instance";
}

OnResponseAction BasicForkStrategy::chooseActionOnResponse(const shared_ptr<BranchInfo>& br) {
	int code = br->getStatus();
	return (code > 100 && code < 300) ? OnResponseAction::Send : OnResponseAction::Wait;
}

ResponseStrategy BasicForkStrategy::chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>&) {
	return ResponseStrategy::Wait;
}

ResponseStrategy BasicForkStrategy::chooseStrategyOnDecisionTimer() {
	return ResponseStrategy::BestElseDefault;
}

ResponseStrategy BasicForkStrategy::chooseStrategyOnLateTimeout() {
	// Never happen, while onDecisionTimer occurs first.
	return ResponseStrategy::BestElseDefault;
}

std::pair<int, const char*> BasicForkStrategy::getDefaultResponse() const {
	return {SIP_408_REQUEST_TIMEOUT};
}

bool BasicForkStrategy::shouldAcceptNextBranches() const {
	return true;
}

void BasicForkStrategy::onCancel(const MsgSip&) {
	LOGE << "Cancel is for INVITE request";
}
} // namespace flexisip