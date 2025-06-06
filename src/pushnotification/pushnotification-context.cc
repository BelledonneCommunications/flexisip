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

#include "pushnotification-context.hh"

#include "agent.hh"
#include "fork-context/fork-call-context.hh"
#include "pushnotification/push-notification-exceptions.hh"
#include "pushnotification/strategy/background-push-strategy.hh"
#include "pushnotification/strategy/remote-push-strategy.hh"
#include "pushnotification/strategy/voip-push-strategy.hh"

using namespace std;

namespace flexisip {

using namespace pushnotification;

void PNContextCall::init(std::chrono::seconds aCallPushInterval, std::chrono::seconds aContextTtl) {
	const auto& root = mModule->getAgent()->getRoot();
	const auto& dests = mPInfo->mDestinations;
	if (dests.find(PushType::VoIP) != dests.cend()) {
		mStrategy = VoIPPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else if (dests.find(PushType::Background) != dests.cend() && !dests.begin()->second->isApns()) {
		// Background strategy is excluded for Apple devices because the rate of background push notifications
		// is limited to 3 per day on this platform.
		mStrategy = BackgroundPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else if (dests.find(PushType::Message) != dests.cend()) {
		auto remoteStrategy = MessagePushStrategy::make(shared_from_this(), root, mModule->getService(), mBranchInfo);
		(void)aCallPushInterval;
		remoteStrategy->setCallPushInterval(aCallPushInterval);
		remoteStrategy->setCallRingingTimeout(aContextTtl + 15s);
		mStrategy = std::move(remoteStrategy);
	} else {
		throw InvalidPushParameters{"no suitable destinations available for PNContextCall"};
	}
}

void PNContextCall::sendPush() {
	mStrategy->sendCallNotification(mPInfo);
}

void PNContextMessage::init() {
	const auto& root = mModule->getAgent()->getRoot();
	if (mPInfo->mDestinations.find(PushType::Message) != mPInfo->mDestinations.cend()) {
		mStrategy = MessagePushStrategy::make(shared_from_this(), root, mModule->getService(), weak_ptr<BranchInfo>{});
	} else if (mPInfo->mDestinations.find(PushType::Background) != mPInfo->mDestinations.cend()) {
		mStrategy = BackgroundPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else {
		throw InvalidPushParameters{"no suitable destinations available for PNContextMessage"};
	}
}

void PNContextMessage::sendPush() {
	mStrategy->sendMessageNotification(mPInfo);
}

void PNContextNotify::init() {
	const auto& root = mModule->getAgent()->getRoot();
	if (mPInfo->mDestinations.find(PushType::Message) != mPInfo->mDestinations.cend()) {
		mStrategy = MessagePushStrategy::make(shared_from_this(), root, mModule->getService(), weak_ptr<BranchInfo>{});
	} else if (mPInfo->mDestinations.find(PushType::Background) != mPInfo->mDestinations.cend()) {
		mStrategy = BackgroundPushStrategy::make(shared_from_this(), root, mModule->getService());
	} else {
		throw InvalidPushParameters{"no suitable destinations available for PNContextNotify"};
	}
}

void PNContextNotify::sendPush() {
	mStrategy->sendMessageNotification(mPInfo);
}

}; // namespace flexisip