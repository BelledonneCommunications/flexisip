/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "flexisip/fork-context/fork-call-context.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/module-pushnotification.hh"

#include "pushnotification/strategy/background-push-strategy.hh"
#include "pushnotification/strategy/remote-push-strategy.hh"
#include "pushnotification/strategy/voip-push-strategy.hh"

#include "pushnotification-context.hh"

using namespace std;

namespace flexisip {

using namespace pushnotification;

PNContextCall::PNContextCall(const std::shared_ptr<OutgoingTransaction>& transaction,
                             PushNotification* _module,
                             const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
							 std::chrono::seconds callPushInterval,
                             const std::string& pnKey)
    : PushNotificationContext{transaction, _module, pInfo, pnKey} {
	mPushSentSatusCode = 180;
	mPushSentPhrase = sip_180_Ringing;

	const auto& root = _module->getAgent()->getRoot();
	const auto& dests = pInfo->mDestinations;
	if (dests.find(PushType::VoIP) != dests.cend()) {
		mStrategy = make_shared<VoIPPushStrategy>(root, _module->getService());
	} else if (dests.find(PushType::Background) != dests.cend() && !dests.begin()->second->isApns()) {
		// Background strategy is excluded for Apple devices because the rate of background push notifications
		// is limited to 3 per day on this platform.
		mStrategy = make_shared<BackgroundPushStrategy>(root, _module->getService());
	} else if (dests.find(PushType::Message) != dests.cend()) {
		auto br = BranchInfo::getBranchInfo(transaction);
		auto remoteStrategy = RemotePushStrategy::make(root, _module->getService(), br);
		remoteStrategy->setCallPushInterval(callPushInterval);
		mStrategy = move(remoteStrategy);
	} else {
		throw runtime_error{"no suitable available destinations for PNContextCall"};
	}
}

void PNContextCall::sendPush() {
	mStrategy->sendCallNotification(mPInfo);
}

PNContextMessage::PNContextMessage(const std::shared_ptr<OutgoingTransaction>& transaction,
                                   PushNotification* _module,
                                   const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
                                   const std::string& pnKey)
    : PushNotificationContext{transaction, _module, pInfo, pnKey} {
	mPushSentSatusCode = 110;
	mPushSentPhrase = "Push sent";

	const auto& root = _module->getAgent()->getRoot();
	if (pInfo->mDestinations.find(PushType::Message) != pInfo->mDestinations.cend()) {
		mStrategy = RemotePushStrategy::make(root, _module->getService(), nullptr);
	} else if (pInfo->mDestinations.find(PushType::Background) != pInfo->mDestinations.cend()) {
		mStrategy = make_shared<BackgroundPushStrategy>(root, _module->getService());
	} else {
		throw runtime_error{"no suitable available destinations for PNContextMessage"};
	}
}

void PNContextMessage::sendPush() {
	mStrategy->sendMessageNotification(mPInfo);
}

}; // namespace flexisip
