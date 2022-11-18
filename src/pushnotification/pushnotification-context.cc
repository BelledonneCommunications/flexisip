/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "pushnotification-context.hh"

#include "flexisip/logmanager.hh"

#include "agent.hh"
#include "fork-context/fork-call-context.hh"
#include "module-pushnotification.hh"
#include "pushnotification/strategy/background-push-strategy.hh"
#include "pushnotification/strategy/remote-push-strategy.hh"
#include "pushnotification/strategy/voip-push-strategy.hh"

using namespace std;

namespace flexisip {

using namespace pushnotification;

void PNContextCall::init(std::chrono::seconds aCallPushInterval) {
	const auto& root = mModule->getAgent()->getRoot();
	const auto& dests = mPInfo->mDestinations;
	if (dests.find(PushType::VoIP) != dests.cend()) {
		mStrategy = VoIPPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else if (dests.find(PushType::Background) != dests.cend() && !dests.begin()->second->isApns()) {
		// Background strategy is excluded for Apple devices because the rate of background push notifications
		// is limited to 3 per day on this platform.
		mStrategy = BackgroundPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else if (dests.find(PushType::Message) != dests.cend()) {
		auto br = BranchInfo::getBranchInfo(mTransaction);
		auto remoteStrategy = RemotePushStrategy::make(shared_from_this(), root, mModule->getService(), br);
		remoteStrategy->setCallPushInterval(aCallPushInterval);
		mStrategy = move(remoteStrategy);
	} else {
		throw runtime_error{"no suitable available destinations for PNContextCall"};
	}
}

void PNContextCall::sendPush() {
	mStrategy->sendCallNotification(mPInfo);
}

void PNContextMessage::init() {
	const auto& root = mModule->getAgent()->getRoot();
	if (mPInfo->mDestinations.find(PushType::Message) != mPInfo->mDestinations.cend()) {
		mStrategy = RemotePushStrategy::make(shared_from_this(), root, mModule->getService(), nullptr);
	} else if (mPInfo->mDestinations.find(PushType::Background) != mPInfo->mDestinations.cend()) {
		mStrategy = BackgroundPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else {
		throw runtime_error{"no suitable available destinations for PNContextMessage"};
	}
}

void PNContextMessage::sendPush() {
	mStrategy->sendMessageNotification(mPInfo);
}

}; // namespace flexisip
