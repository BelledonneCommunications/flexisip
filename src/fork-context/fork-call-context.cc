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

#include "fork-call-context.hh"

#include <algorithm>
#include <memory>
#include <string_view>

#include <sofia-sip/sip_status.h>

#include "agent.hh"
#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/fork-status.hh"
#include "registrar/extended-contact.hh"

using namespace std;
using namespace string_view_literals;

namespace flexisip {
using namespace pushnotification;

template <typename T>
static bool contains(const list<T>& l, T value) {
	return find(l.cbegin(), l.cend(), value) != l.cend();
}

ForkCallContext::CancelInfo::CancelInfo(sofiasip::Home& home, const ForkStatus& status) : mStatus{status} {
	if (status == ForkStatus::AcceptedElsewhere) {
		mReason = sip_reason_make(home.home(), "SIP;cause=200;text=\"Call completed elsewhere\"");
	} else if (status == ForkStatus::DeclinedElsewhere) {
		mReason = sip_reason_make(home.home(), "SIP;cause=600;text=\"Busy Everywhere\"");
	}
	// else mReason remains empty
}

ForkCallContext::CancelInfo::CancelInfo(sip_reason_t* reason) : mReason(reason) {
	string_view code = reason && reason->re_cause ? reason->re_cause : "";
	if (code == "200"sv) {
		mStatus = ForkStatus::AcceptedElsewhere;
	} else if (code == "600"sv) {
		mStatus = ForkStatus::DeclinedElsewhere;
	} else mStatus = ForkStatus::Standard;
}

ForkCallContext::ForkCallContext(const shared_ptr<ModuleRouter>& router,
                                 std::unique_ptr<RequestSipEvent>&& event,
                                 sofiasip::MsgSipPriority priority)
    : ForkContextBase(router,
                      router->getAgent(),
                      router->getCallForkCfg(),
                      router,
                      std::move(event),
                      router->mStats.mCountCallForks,
                      priority),
      mLog{getEvent().getEventLog<CallLog>()} {
	SLOGD << "New ForkCallContext " << this;
}

ForkCallContext::~ForkCallContext() {
	SLOGD << "Destroy ForkCallContext " << this;
	if (mIncoming) {
		getEvent().reply(SIP_503_SERVICE_UNAVAILABLE, TAG_END());
	}
}

void ForkCallContext::onCancel(const MsgSip& ms) {
	mLog->setCancelled();
	mLog->setCompleted();
	mCancelled = true;
	cancelAll(ms.getSip());

	if (shouldFinish()) {
		setFinished();
	} else {
		checkFinished();
	}
}

void ForkCallContext::cancelOthers(const shared_ptr<BranchInfo>& br) {
	if (!mCancel.has_value()) {
		mCancel = make_optional<CancelInfo>(mHome, ForkStatus::Standard);
	}

	const auto branches = getBranches(); // work on a copy of the list of branches
	for (const auto& brit : branches) {
		if (brit != br) {
			cancelBranch(brit);
			brit->notifyBranchCanceled(mCancel->mStatus);

			auto& event = getEvent();
			auto eventLog = make_shared<CallLog>(event.getMsgSip()->getSip());
			eventLog->setDevice(*brit->mContact);
			eventLog->setCancelled();
			eventLog->setForkStatus(mCancel->mStatus);
			event.writeLog(eventLog);
		}
	}
	mNextBranchesTimer.reset();
}

void ForkCallContext::cancelAll(const sip_t* received_cancel) {
	if (!mCancel.has_value() && received_cancel && received_cancel->sip_reason) {
		mCancel = make_optional<CancelInfo>(sip_reason_dup(mHome.home(), received_cancel->sip_reason));
	}
	cancelOthers(nullptr);
}

void ForkCallContext::cancelOthersWithStatus(const shared_ptr<BranchInfo>& br, ForkStatus status) {
	if (!mCancel.has_value()) {
		mCancel = make_optional<CancelInfo>(mHome, status);
	}
	cancelOthers(br);
}

void ForkCallContext::cancelBranch(const std::shared_ptr<BranchInfo>& brit) {
	auto& tr = brit->mTransaction;
	if (tr && brit->getStatus() < 200) {
		if (mCancel && mCancel->mReason) tr->cancelWithReason(mCancel->mReason);
		else tr->cancel();
	}
}

const int ForkCallContext::sUrgentCodesWithout603[] = {401, 407, 415, 420, 484, 488, 606, 0};

const int* ForkCallContext::getUrgentCodes() {
	if (mCfg->mTreatAllErrorsAsUrgent) return ForkContextBase::sAllCodesUrgent;

	if (mCfg->mTreatDeclineAsUrgent) return ForkContextBase::sUrgentCodes;

	return sUrgentCodesWithout603;
}

void ForkCallContext::onResponse(const shared_ptr<BranchInfo>& br, ResponseSipEvent& event) {
	SLOGD << "ForkCallContext[" << this << "]::onResponse()";

	ForkContextBase::onResponse(br, event);

	const auto code = event.getMsgSip()->getSip()->sip_status->st_status;
	if (code >= 300) {
		/*
		 * In fork-late mode, we must not consider that 503 and 408 response codes (which are sent by sofia in case of
		 * i/o error or timeouts) are branches that are answered. Instead, we must wait for the duration of the fork for
		 * new registers.
		 */
		if (code >= 600) {
			/*6xx response are normally treated as global failures */
			if (!mCfg->mForkNoGlobalDecline) {
				mCancelled = true;
				cancelOthersWithStatus(br, ForkStatus::DeclinedElsewhere);
			}
		} else if (isUrgent(code, getUrgentCodes()) && mShortTimer == nullptr) {
			mShortTimer = make_unique<sofiasip::Timer>(mAgent->getRoot());
			mShortTimer->set([this]() { onShortTimer(); }, mCfg->mUrgentTimeout);
		}
	} else if (code >= 200) {
		forwardThenLogResponse(br);
		mCancelled = true;
		cancelOthersWithStatus(br, ForkStatus::AcceptedElsewhere);
	} else if (code >= 100) {
		if (code == 180) {
			auto& event = getEvent();
			event.writeLog(make_shared<CallRingingEventLog>(*event.getMsgSip()->getSip(), br.get()));
		}

		forwardThenLogResponse(br);
	}

	if (auto forwardedBr = checkFinished(); forwardedBr) {
		logResponse(forwardedBr->mLastResponseEvent, forwardedBr.get());
	}
}

void ForkCallContext::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	ForkContextBase::onPushSent(aPNCtx, aRingingPush); // Send "110 Push sent"
	if (aRingingPush && !isRingingSomewhere()) {
		sendResponse(180, sip_180_Ringing, aPNCtx.toTagEnabled());
	}
}

void ForkCallContext::forwardThenLogResponse(const shared_ptr<BranchInfo>& branch) {
	if (forwardResponse(branch)) logResponse(branch->mLastResponseEvent, branch.get());
}

void ForkCallContext::logResponse(const std::unique_ptr<ResponseSipEvent>& ev, const BranchInfo* branch) {
	if (ev) {
		if (branch) {
			mLog->setDevice(*branch->mContact);
		}

		sip_t* sip = ev->getMsgSip()->getSip();
		mLog->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);

		if (sip->sip_status->st_status >= 200) mLog->setCompleted();

		ev->setEventLog(mLog);
	}
}

void ForkCallContext::onNewRegister(const SipUri& dest,
                                    const std::string& uid,
                                    const std::shared_ptr<ExtendedContact>& newContact) {

	SLOGD << "ForkCallContext[" << this << "]::onNewRegister()";
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
			if (pushContext->getPushInfo()->isApple() && pushContext->getStrategy()->getPushType() == PushType::VoIP) {
				const auto& dispatchedBranch = sharedListener->onDispatchNeeded(shared_from_this(), newContact);
				cancelBranch(dispatchedBranch);
				checkFinished();
				return;
			}
		}
	}

	sharedListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
	                                              DispatchStatus::DispatchNotNeeded);
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

	auto br = findBestBranch(mCfg->mForkLate);

	if (br) forwardThenLogResponse(br);
}

void ForkCallContext::onLateTimeout() {
	if (mIncoming) {
		if (auto br = findBestBranch(mCfg->mForkLate); !br || br->getStatus() == 0) {
			// Forward then log _custom_ response
			logResponse(forwardCustomResponse(SIP_408_REQUEST_TIMEOUT), br.get());
		} else {
			forwardThenLogResponse(br);
		}

		/*cancel all possibly pending outgoing transactions*/
		cancelOthers(shared_ptr<BranchInfo>());
	}
}

void ForkCallContext::processInternalError(int status, const char* phrase) {
	ForkContextBase::processInternalError(status, phrase);
	cancelOthers(shared_ptr<BranchInfo>());
}

void ForkCallContext::start() {
	if (isCompleted()) return;

	bool firstStart = mCurrentPriority == -1;
	if (firstStart) {
		// SOUNDNESS: getBranches() returns the waiting branches. We want all the branches in the event, so that
		// presumes there are no branches answered yet. We also presume all branches have been added by now.
		auto& event = getEvent();
		event.writeLog(make_shared<CallStartedEventLog>(*event.getMsgSip()->getSip(), getBranches()));
	}

	ForkContextBase::start();
}

std::shared_ptr<BranchInfo> ForkCallContext::checkFinished() {
	if (auto br = ForkContextBase::checkFinished(); (mIncoming == nullptr && !mCfg->mForkLate) || br) {
		return br;
	}

	if (mCancelled) {
		// If a call is cancelled by caller/callee, even if some branches only answered 503 or 408, even in fork-late
		// mode, we want to directly send a response.
		auto br = findBestBranch(false);
		if (br && forwardResponse(br)) {
			return br;
		}
	}

	return nullptr;
}

} // namespace flexisip