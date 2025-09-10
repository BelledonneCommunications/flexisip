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

using namespace std;

namespace flexisip {

using namespace pushnotification;

CancelInfo::CancelInfo(sip_reason_t* reason) : mReason(reason) {
	string_view code = reason && reason->re_cause ? reason->re_cause : "";
	if (code == "200"sv) {
		mStatus = ForkStatus::AcceptedElsewhere;
	} else if (code == "600"sv) {
		mStatus = ForkStatus::DeclinedElsewhere;
	} else {
		mStatus = ForkStatus::Standard;
	}
}

CancelInfo::CancelInfo(sofiasip::Home& home, const ForkStatus& status) : mStatus{status} {
	if (status == ForkStatus::AcceptedElsewhere) {
		mReason = sip_reason_make(home.home(), "SIP;cause=200;text=\"Call completed elsewhere\"");
	} else if (status == ForkStatus::DeclinedElsewhere) {
		mReason = sip_reason_make(home.home(), "SIP;cause=600;text=\"Busy Everywhere\"");
	}
	// else mReason remains empty
}

BranchInfo::BranchInfo(unique_ptr<RequestSipEvent>&& ev,
                       const shared_ptr<ForkContext>& context,
                       const shared_ptr<ExtendedContact>& contact,
                       const weak_ptr<BranchInfoListener>& listener,
                       const weak_ptr<PushNotificationContext>& pushContext,
                       int clearedCount)
    : mRequestEvent(std::move(ev)), mForkCtx(context), mContact(contact), mRequestMsg(mRequestEvent->getMsgSip()),
      mTransaction(mRequestEvent->createOutgoingTransaction()), mUid(mContact->mKey), mPriority(mContact->mQ),
      mListener(listener), mClearedCount(clearedCount), mPushContext(pushContext),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "BranchInfo")) {
	// Unlink the incoming and outgoing transactions that are done by default, since now the fork context is managing
	// them.
	mRequestEvent->unlinkTransactions();
}

shared_ptr<BranchInfo> BranchInfo::getBranchInfo(const shared_ptr<OutgoingTransaction>& tr) {
	return tr ? tr->getProperty<BranchInfo>("BranchInfo") : nullptr;
}

void BranchInfo::setBranchInfo(const shared_ptr<OutgoingTransaction>& tr, const weak_ptr<BranchInfo>& br) {
	if (tr) tr->setProperty("BranchInfo", br);
}

void BranchInfo::notifyBranchCanceled(ForkStatus cancelReason) noexcept {
	if (auto listener = mListener.lock()) listener->onBranchCanceled(shared_from_this(), cancelReason);
}

void BranchInfo::notifyBranchCompleted() noexcept {
	if (auto listener = mListener.lock()) listener->onBranchCompleted(shared_from_this());
}

void BranchInfo::processResponse(ResponseSipEvent& event) {
	LOGD << "Processing response";
	mLastResponseEvent = make_unique<ResponseSipEvent>(event); // make a copy
	mLastResponse = mLastResponseEvent->getMsgSip();

	mLastResponseEvent->suspendProcessing();

	auto forkCtx = mForkCtx.lock();
	forkCtx->onResponse(shared_from_this(), *mLastResponseEvent);

	// The event may go through, but it will not be sent.
	event.setIncomingAgent(nullptr);

	// A response has been submitted, else, it has been retained.
	if (!mLastResponseEvent || !mLastResponseEvent->isSuspended()) {
		// mLastResponseEvent has been resubmitted, so stop the original event.
		event.terminateProcessing();
	}

	if (forkCtx->allCurrentBranchesAnswered(FinalStatusMode::RFC) && forkCtx->hasNextBranches()) forkCtx->start();
}

int BranchInfo::getStatus() const {
	return mLastResponse ? mLastResponse->getSip()->sip_status->st_status : 0;
}

bool BranchInfo::needsDelivery(FinalStatusMode mode) const {
	const auto currentStatus = getStatus();

	switch (mode) {
		case FinalStatusMode::ForkLate:
			return currentStatus < 200 || currentStatus == 503 || currentStatus == 408;
		case FinalStatusMode::RFC:
		default:
			return currentStatus < 200;
	}
}

BranchInfoDb BranchInfo::getDbObject() const {
	const string request{mRequestMsg->msgAsString()};
	const string lastResponse{mLastResponse->msgAsString()};
	return {mUid, mPriority, request, lastResponse, mClearedCount};
}

unique_ptr<RequestSipEvent>&& BranchInfo::extractRequest() {
	return std::move(mRequestEvent);
}

string BranchInfo::getUid() const {
	return mUid;
}

optional<SipUri> BranchInfo::getRequestUri() const {
	if (mRequestMsg == nullptr) return nullopt;
	if (mRequestMsg->getSip() == nullptr) return nullopt;
	if (mRequestMsg->getSip()->sip_request == nullptr) return nullopt;
	try {
		return SipUri{mRequestMsg->getSip()->sip_request->rq_url};
	} catch (const exception& exception) {
		LOGD << "Failed to get request URI: " << exception.what();
		return nullopt;
	}
}

float BranchInfo::getPriority() const {
	return mPriority;
}

int BranchInfo::getClearedCount() const {
	return mClearedCount;
}

weak_ptr<BranchInfoListener> BranchInfo::getListener() const {
	return mListener;
}

shared_ptr<const ExtendedContact> BranchInfo::getContact() const {
	return mContact;
}

void BranchInfo::setListener(const weak_ptr<BranchInfoListener>& listener) {
	mListener = listener;
}

shared_ptr<ForkContext> BranchInfo::getForkContext() const {
	return mForkCtx.lock();
}

const unique_ptr<ResponseSipEvent>& BranchInfo::getLastResponseEvent() const {
	return mLastResponseEvent;
}

shared_ptr<PushNotificationContext> BranchInfo::getPushNotificationContext() const {
	return mPushContext.lock();
}

shared_ptr<MsgSip> BranchInfo::getRequestMsg() const {
	return mRequestMsg;
}

void BranchInfo::setForkContext(const shared_ptr<ForkContext>& forkContext) {
	mForkCtx = forkContext;
}

void BranchInfo::setPushNotificationContext(const shared_ptr<PushNotificationContext>& context) {
	mPushContext = context;
}

bool BranchInfo::forwardResponse(bool forkContextHasIncomingTransaction) {
	if (mLastResponseEvent == nullptr) {
		LOGE << "No response received on this branch";
		return false;
	}

	if (!forkContextHasIncomingTransaction) {
		mLastResponseEvent->setIncomingAgent(nullptr);
		return false;
	}

	const int statusCode = getStatus();
	if (const auto forkContext = mForkCtx.lock())
		mLastResponseEvent = forkContext->onForwardResponse(std::move(mLastResponseEvent));

	if (statusCode >= 200) mTransaction.reset();
	return true;
}

bool BranchInfo::pushContextIsAppleVoIp() const {
	if (const auto pushContext = getPushNotificationContext())
		return pushContext->getPushInfo()->isApple() && pushContext->getStrategy()->getPushType() == PushType::VoIP;

	return false;
}

void BranchInfo::cancel(const std::optional<CancelInfo>& information, bool keepAppleVoIpAlive) {
	if (!mTransaction || getStatus() >= 200) return;

	if (keepAppleVoIpAlive && !mWaitingAppleClientResponse && getStatus() == 0 && pushContextIsAppleVoIp()) {
		mWaitingAppleClientResponse = true;
		LOGD << "Cancel requested but this branch (iOS client) did not receive any response for the moment (status = "
		     << getStatus() << "): waiting for a response or 'call-fork-timeout'";
		return;
	}

	LOGD << "Cancel requested (status = '" << getStatus() << "')";

	if (information && information->mReason) mTransaction->cancelWithReason(information->mReason);
	else mTransaction->cancel();
}

} // namespace flexisip