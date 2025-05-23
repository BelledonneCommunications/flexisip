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

#include "remote-push-strategy.hh"

#include "pushnotification/push-notification-exceptions.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

void MessagePushStrategy::sendMessageNotification(const std::shared_ptr<const PushInfo>& pInfo) {
	mLogPrefix = LogManager::makeLogPrefixForInstance(this, "MessagePushStrategy");
	auto req = mService->makeRequest(PushType::Message, pInfo);
	mService->sendPush(req);
	notifyPushSent();
}

void MessagePushStrategy::sendCallNotification(const std::shared_ptr<const PushInfo>& pInfo) {
	using namespace std::chrono;

	auto br = mBranchInfo.lock();
	if (br == nullptr) {
		throw InvalidSendParameters{"no associated branch found (it may not exist anymore)"};
	}

	br->setListener(shared_from_this());

	mCallPushInfo = std::make_shared<PushInfo>(*pInfo);
	mCallPushInfo->mTtl = 0s;
	mCallPushInfo->mCollapseId = mCallPushInfo->mCallId;

	auto sendPush = [this]() {
		LOGI_CTX(mLogPrefix, "sendCallNotification") << "Sending ringing push notification";
		auto req = mService->makeRequest(PushType::Message, mCallPushInfo);
		mService->sendPush(req);
	};
	sendPush();
	notifyPushSent(true);

	if (pushRepetitionEnabled()) {
		auto pushTimer = std::make_shared<sofiasip::Timer>(mRoot, mCallPushInterval);
		pushTimer->setForEver(sendPush);

		// This lambda aims to take the ownership on 'pushTimer'. It is to be
		// given to mCallRingingTimeoutTimer which will destroy the lambda (and 'pushTimer' by extension)
		// when it expires. Thus, sendPush() lambda will be run regularly until mCallRingingTimouteTimer
		// expires.
		auto onRingingTimeout = [pushTimer]() {};

		mCallRingingTimeoutTimer = std::make_unique<sofiasip::Timer>(mRoot, mCallRingingTimeout);
		mCallRingingTimeoutTimer->set(onRingingTimeout);
	}
}

void MessagePushStrategy::onBranchCanceled([[maybe_unused]] const std::shared_ptr<BranchInfo>& br,
                                           ForkStatus cancelReason) noexcept {
	if (!pushRepetitionEnabled()) {
		// Avoid final PN to be sent if repetition hasn't been enabled.
		return;
	}

	// Stop sending ringing push notifications
	LOGD << "Stop sending ringing message PN";
	mCallRingingTimeoutTimer.reset();

	// Send the final PN
	try {
		LOGD << "Sending last message PN";
		switch (cancelReason) {
			case ForkStatus::AcceptedElsewhere:
				mCallPushInfo->mAlertMsgId = mCallPushInfo->mAcceptedElsewhereMsg;
				break;
			case ForkStatus::DeclinedElsewhere:
				mCallPushInfo->mAlertMsgId = mCallPushInfo->mDeclinedElsewhereMsg;
				break;
			case ForkStatus::Standard:
				mCallPushInfo->mAlertMsgId = mCallPushInfo->mMissingCallMsg;
				break;
		}
		auto req = mService->makeRequest(PushType::Message, mCallPushInfo);
		mService->sendPush(req);
	} catch (const std::runtime_error& e) {
		LOGE << "Last message PN sending failed: " << e.what();
	}
}

void MessagePushStrategy::onBranchCompleted(const std::shared_ptr<BranchInfo>& br) noexcept {
	if (!pushRepetitionEnabled()) {
		// Avoid final PN to be sent if repetition hasn't been enabled.
		return;
	}

	auto status = br->getStatus();
	if (status != 408 && status != 503) {
		LOGD << "Stop sending ringing message PN";
		mCallRingingTimeoutTimer.reset();
	}
}

} // namespace pushnotification
} // namespace flexisip