/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>

#include <sofia-sip/sip_status.h>

#include "flexisip/common.hh"

#include "flexisip/fork-context/fork-call-context.hh"

using namespace std;

namespace flexisip {

template <typename T>
static bool contains(const list<T>& l, T value) {
	return find(l.cbegin(), l.cend(), value) != l.cend();
}

ForkCallContext::ForkCallContext(const shared_ptr<ModuleRouter>& router,
                                 const std::shared_ptr<RequestSipEvent>& event,
                                 sofiasip::MsgSipPriority priority)
    : ForkContextBase(router, event, router->getCallForkCfg(), router, router->mStats.mCountCallForks, priority),
      mLog{event->getEventLog<CallLog>()} {
	SLOGD << "New ForkCallContext " << this;
}

ForkCallContext::~ForkCallContext() {
	SLOGD << "Destroy ForkCallContext " << this;
}

void ForkCallContext::onCancel(const shared_ptr<RequestSipEvent>& ev) {
	mLog->setCancelled();
	mLog->setCompleted();
	mCancelled = true;
	cancelOthers(nullptr, ev->getSip());
	// The event log must be placed in a sip event in order to be written into DB.
	ev->setEventLog(mLog);

	if (shouldFinish()) {
		setFinished();
	}
}

void ForkCallContext::cancelOthers(const shared_ptr<BranchInfo>& br, sip_t* received_cancel) {
	if (!mCancelReason) {
		if (received_cancel && received_cancel->sip_reason) {
			mCancelReason = sip_reason_dup(mHome.home(), received_cancel->sip_reason);
		}
	}
	const auto branches = getBranches(); // work on a copy of the list of branches
	for (const auto& brit : branches) {
		if (brit != br) {
			cancelBranch(brit);
			brit->notifyBranchCanceled(ForkStatus::Standard);
		}
	}
	mNextBranchesTimer.reset();
}

void ForkCallContext::cancelOthersWithStatus(const shared_ptr<BranchInfo>& br, ForkStatus status) {
	if (!mCancelReason) {
		if (status == ForkStatus::AcceptedElsewhere) {
			mCancelReason = sip_reason_make(mHome.home(), "SIP;cause=200;text=\"Call completed elsewhere\"");
		} else if (status == ForkStatus::DeclineElsewhere) {
			mCancelReason = sip_reason_make(mHome.home(), "SIP;cause=600;text=\"Busy Everywhere\"");
		}
	}

	const auto branches = getBranches(); // work on a copy of the list of branches
	for (const auto& brit : branches) {
		if (brit != br) {
			cancelBranch(brit);
			brit->notifyBranchCanceled(status);
		}
	}
	mNextBranchesTimer.reset();
}

void ForkCallContext::cancelBranch(const std::shared_ptr<BranchInfo>& brit) {
	auto& tr = brit->mTransaction;
	if (tr && brit->getStatus() < 200) {
		if (mCancelReason) tr->cancelWithReason(mCancelReason, brit);
		else tr->cancel(brit);
	}

	if (!mCfg->mForkLate) removeBranch(brit);
}

const int ForkCallContext::sUrgentCodesWithout603[] = {401, 407, 415, 420, 484, 488, 606, 0};

const int* ForkCallContext::getUrgentCodes() {
	if (mCfg->mTreatAllErrorsAsUrgent) return ForkContextBase::sAllCodesUrgent;

	if (mCfg->mTreatDeclineAsUrgent) return ForkContextBase::sUrgentCodes;

	return sUrgentCodesWithout603;
}

void ForkCallContext::onResponse(const shared_ptr<BranchInfo>& br, const shared_ptr<ResponseSipEvent>& event) {
	LOGD("ForkCallContext[%p]::onResponse()", this);

	ForkContextBase::onResponse(br, event);

	const auto code = event->getMsgSip()->getSip()->sip_status->st_status;
	if (code >= 300) {
		/*
		 * In fork-late mode, we must not consider that 503 and 408 response codes (which are sent by sofia in case of
		 * i/o error or timeouts) are branches that are answered. Instead, we must wait for the duration of the fork for
		 * new registers.
		 */
		if (code >= 600) {
			/*6xx response are normally treated as global failures */
			if (!mCfg->mForkNoGlobalDecline) {
				logResponse(forwardResponse(br));
				mCancelled = true;
				cancelOthersWithStatus(br, ForkStatus::DeclineElsewhere);
			}
		} else if (allBranchesAnswered(mCfg->mForkLate)) {
			shared_ptr<BranchInfo> best = findBestBranch(getUrgentCodes(), mCfg->mForkLate);
			if (best) logResponse(forwardResponse(best));
		} else if (isUrgent(code, getUrgentCodes()) && mShortTimer == nullptr) {
			mShortTimer = make_unique<sofiasip::Timer>(mAgent->getRoot());
			mShortTimer->set([this]() { onShortTimer(); }, mCfg->mUrgentTimeout);
		}
	} else if (code >= 200) {
		logResponse(forwardResponse(br));
		mCancelled = true;
		cancelOthersWithStatus(br, ForkStatus::AcceptedElsewhere);
	} else if (code >= 100) {
		logResponse(forwardResponse(br));
	}

	checkFinished();
}

void ForkCallContext::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	ForkContextBase::onPushSent(aPNCtx, aRingingPush); // Send "110 Push sent"
	if (aRingingPush && !isRingingSomewhere()) {
		sendResponse(180, sip_180_Ringing, aPNCtx.toTagEnabled());
	}
}

void ForkCallContext::logResponse(const shared_ptr<ResponseSipEvent>& ev) {
	if (ev) {
		sip_t* sip = ev->getMsgSip()->getSip();
		mLog->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);

		if (sip->sip_status->st_status >= 200) mLog->setCompleted();

		ev->setEventLog(mLog);
	}
}

void ForkCallContext::onNewRegister(const SipUri& dest,
                                    const std::string& uid,
                                    const std::shared_ptr<ExtendedContact>& newContact) {

	LOGD("ForkCallContext[%p]::onNewRegister()", this);
	const auto& sharedListener = mListener.lock();
	if (!sharedListener) {
		return;
	}

	if (isCompleted() && !mCfg->mForkLate) {
		sharedListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
		                                              DispatchStatus::DispatchNotNeeded);
		return;
	}

	const auto dispatchPair = shouldDispatch(dest, uid);

	if (dispatchPair.first != DispatchStatus::DispatchNeeded) {
		sharedListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, dispatchPair.first);
		return;
	}

	if (!isCompleted()) {
		sharedListener->onDispatchNeeded(shared_from_this(), newContact);
		checkFinished();
		return;
	} else if (dispatchPair.second) {
		if (auto pushContext = dispatchPair.second->pushContext.lock()) {
			if (pushContext->getPushInfo()->isApple()) {
				const auto& dispatchedBranch = sharedListener->onDispatchNeeded(shared_from_this(), newContact);
				cancelBranch(dispatchedBranch);
				checkFinished();
				return;
			}
		}
	}

	sharedListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
	                                              DispatchStatus::DispatchNotNeeded);
	return;
}

bool ForkCallContext::isCompleted() const {
	if (getLastResponseCode() >= 200 || mCancelled || mIncoming == NULL) return true;

	return false;
}

bool ForkCallContext::isRingingSomewhere() const {
	for (const auto& br : getBranches()) {
		auto status = br->getStatus();
		if (status >= 180 && status < 200) return true;
	}
	return false;
}

void ForkCallContext::onShortTimer() {
	SLOGD << "ForkCallContext [" << this << "]: time to send urgent replies";

	/*first stop the timer, it has to be one shot*/
	mShortTimer.reset();

	if (isRingingSomewhere()) return; /*it's ringing somewhere*/

	auto br = findBestBranch(getUrgentCodes(), mCfg->mForkLate);

	if (br) logResponse(forwardResponse(br));
}

void ForkCallContext::onLateTimeout() {
	if (mIncoming) {
		auto br = findBestBranch(getUrgentCodes(), mCfg->mForkLate);

		if (!br || br->getStatus() == 0 || br->getStatus() == 503) {
			logResponse(forwardCustomResponse(SIP_408_REQUEST_TIMEOUT));
		} else {
			logResponse(forwardResponse(br));
		}

		/*cancel all possibly pending outgoing transactions*/
		cancelOthers(shared_ptr<BranchInfo>(), nullptr);
	}
}

void ForkCallContext::processInternalError(int status, const char* phrase) {
	ForkContextBase::processInternalError(status, phrase);
	cancelOthers(shared_ptr<BranchInfo>(), nullptr);
}

void ForkCallContext::start() {
	if (!isCompleted()) {
		ForkContextBase::start();
	}
}

} // namespace flexisip
