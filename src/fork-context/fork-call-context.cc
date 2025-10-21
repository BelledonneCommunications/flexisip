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

#include "sofia-sip/sip_status.h"

#include "agent.hh"
#include "branch-info.hh"
#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/fork-status.hh"
#include "modules/module-pushnotification.hh"
#include "registrar/extended-contact.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace string_view_literals;

namespace flexisip {

using namespace pushnotification;

ForkCallContext::ForkCallContext(std::unique_ptr<RequestSipEvent>&& event,
                                 sofiasip::MsgSipPriority priority,
                                 const std::weak_ptr<ForkContextListener>& forkContextListener,
                                 const std::weak_ptr<InjectorListener>& injectorListener,
                                 AgentInterface* agent,
                                 const std::shared_ptr<ForkContextConfig>& config,
                                 const std::weak_ptr<StatPair>& counter)
    : ForkContextBase{agent, config, injectorListener, forkContextListener, std::move(event), counter, priority},
      mLog{ForkContextBase::getEvent().getEventLog<CallLog>()},
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "ForkCallContext")} {
	LOGD << "New instance";
}

ForkCallContext::~ForkCallContext() {
	LOGD << "Destroy instance";
	if (mIncoming && mIncoming->getStatus() < 200)
		ForkContextBase::getEvent().reply(SIP_503_SERVICE_UNAVAILABLE, TAG_END());
}

void ForkCallContext::onCancel(const MsgSip& ms) {
	LOGD << "Canceling fork";
	mLog->setCancelled();
	mLog->setCompleted();
	mCancelled = true;
	cancelAll(ms.getSip());

	if (shouldFinish()) setFinished();
	else tryToSendFinalResponse();
}

void ForkCallContext::cancelOthers(const shared_ptr<BranchInfo>& br) {
	if (!mCancel.has_value()) mCancel = make_optional<CancelInfo>(mHome, ForkStatus::Standard);

	// WARNING: work on a copy of the list.
	const auto branches = getBranches();

	for (const auto& branch : branches) {
		if (branch == br) continue;

		branch->cancel(mCancel, true);
		// Always notify here, even if the branch is not canceled (due to status or iOS devices specific reasons).
		branch->notifyBranchCanceled(mCancel->mStatus);

		auto& event = getEvent();
		auto eventLog = make_shared<CallLog>(event.getMsgSip()->getSip());
		eventLog->setDevice(*branch->getContact());
		eventLog->setCancelled();
		eventLog->setForkStatus(mCancel->mStatus);
		event.writeLog(eventLog);
	}
	mNextBranchesTimer.stop();
}

void ForkCallContext::cancelAll(const sip_t* received_cancel) {
	if (!mCancel.has_value() && received_cancel && received_cancel->sip_reason)
		mCancel = make_optional<CancelInfo>(sip_reason_dup(mHome.home(), received_cancel->sip_reason));

	cancelOthers(nullptr);
}

void ForkCallContext::cancelOthersWithStatus(const shared_ptr<BranchInfo>& br, ForkStatus status) {
	if (!mCancel.has_value()) mCancel = make_optional<CancelInfo>(mHome, status);

	cancelOthers(br);
}

const int* ForkCallContext::getUrgentCodes() const {
	if (mCfg->mTreatAllErrorsAsUrgent) return kAllCodesUrgent;
	if (mCfg->mTreatDeclineAsUrgent) return kUrgentCodes;
	return kUrgentCodesWithout603;
}

void ForkCallContext::onResponse(const shared_ptr<BranchInfo>& br, ResponseSipEvent& event) {
	LOGD << "Running " << __func__;

	ForkContextBase::onResponse(br, event);

	if (const auto code = event.getStatusCode(); code >= 300) {
		/*
		 * In fork-late mode, we must not consider that 503 and 408 response codes (which are sent by sofia in case of
		 * i/o error or timeouts) are branches that are answered. Instead, we must wait for the duration of the fork for
		 * new registers.
		 */
		if (code >= 600) {
			// 6xx responses are normally processed as global failures.
			if (!mCfg->mForkNoGlobalDecline) {
				mCancelled = true;
				cancelOthersWithStatus(br, ForkStatus::DeclinedElsewhere);
			}
		} else if (isUrgent(code, getUrgentCodes()) && mShortTimer == nullptr) {
			mShortTimer = make_unique<sofiasip::Timer>(mAgent->getRoot());
			mShortTimer->set([this]() { onShortTimer(); }, mCfg->mUrgentTimeout);
		}
	} else if (code >= 200) {
		sendAndLogResponse(br);
		mCancelled = true;
		cancelOthersWithStatus(br, ForkStatus::AcceptedElsewhere);
	} else if (code >= 100 && br != mCallForwardingBranch.lock()) {
		if (code == 180) {
			auto& request = getEvent();
			request.writeLog(make_shared<CallRingingEventLog>(*request.getMsgSip()->getSip(), br.get()));
		}

		if (!mCancelled) sendAndLogResponse(br);
	}

	if (isFinished()) return;
	if (const auto branch = tryToSendFinalResponse()) logResponse(branch->getLastResponseEvent(), branch.get());
}

void ForkCallContext::setFinished() {
	if (mLateTimer.hasAlreadyExpiredOnce() && mCallForwardingBranch.lock()) return;
	ForkContextBase::setFinished();
}

void ForkCallContext::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	ForkContextBase::onPushSent(aPNCtx, aRingingPush); // Send "110 Push sent"
	if (aRingingPush && !isRingingSomewhere()) sendResponse(180, sip_180_Ringing, aPNCtx.toTagEnabled());
}

void ForkCallContext::sendAndLogResponse(const shared_ptr<BranchInfo>& branch) const {
	if (branch->sendResponse(mIncoming != nullptr) && branch != mCallForwardingBranch.lock())
		logResponse(branch->getLastResponseEvent(), branch.get());
}

bool ForkCallContext::callForwardingEnabled() const {
	const auto config = static_pointer_cast<ForkCallContextConfig>(mCfg);
	return !config->mVoicemailServerUri.empty();
}

void ForkCallContext::logResponse(const std::unique_ptr<ResponseSipEvent>& ev, const BranchInfo* branch) const {
	if (ev == nullptr) return;

	if (branch) mLog->setDevice(*branch->getContact());

	const auto* sip = ev->getMsgSip()->getSip();
	mLog->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);

	if (sip->sip_status->st_status >= 200) mLog->setCompleted();

	ev->setEventLog(mLog);
}

void ForkCallContext::onNewRegister(const SipUri& dest,
                                    const std::string& uid,
                                    const std::shared_ptr<ExtendedContact>& newContact) {
	LOGD << "Received new registration notification";
	const auto forkContextListener = mForkContextListener.lock();
	if (!forkContextListener) return;

	if (isCompleted() && !mCfg->mForkLate) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
		                                                   DispatchStatus::DispatchNotNeeded);
		return;
	}

	const auto [status, branch] = shouldDispatch(dest, uid);

	if (status != DispatchStatus::DispatchNeeded) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, status);
		return;
	}

	if (!isCompleted()) {
		forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
		tryToSendFinalResponse();
		return;
	}

	if (branch && branch->pushContextIsAppleVoIp()) {
		const auto& dispatchedBranch = forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
		dispatchedBranch->cancel(mCancel);
		tryToSendFinalResponse();
		return;
	}

	forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
	                                                   DispatchStatus::DispatchNotNeeded);
}

bool ForkCallContext::isCompleted() const {
	if (getLastResponseCode() >= 200 || mCancelled || !mIncoming) return true;

	return false;
}

bool ForkCallContext::isRingingSomewhere() const {
	return any_of(mWaitingBranches.cbegin(), mWaitingBranches.cend(), [](const auto& br) {
		const auto status = br->getStatus();
		return status >= 180 && status < 200;
	});
}

void ForkCallContext::onShortTimer() {
	LOGD << "Time to send urgent replies";

	// First, stop the timer; it has to be one shot.
	mShortTimer.reset();

	if (isRingingSomewhere()) return;

	if (const auto br = findBestBranch(mCfg->mForkLate)) sendAndLogResponse(br);
}

void ForkCallContext::onLateTimeout() {
	if (!mIncoming) return;

	// Cancel all possibly pending outgoing transactions.
	cancelOthers(nullptr);

	if (callForwardingEnabled()) {
		forward(408);
		return;
	}

	if (const auto br = findBestBranch(mCfg->mForkLate); !br || br->getStatus() == 0)
		logResponse(sendCustomResponse(SIP_408_REQUEST_TIMEOUT), br.get());
	else sendAndLogResponse(br);
}

void ForkCallContext::processInternalError(int status, const char* phrase) {
	ForkContextBase::processInternalError(status, phrase);
	cancelOthers(nullptr);
}

void ForkCallContext::start() {
	if (isCompleted()) return;

	bool firstStart = mCurrentPriority == -1.f;
	if (firstStart) {
		// SOUNDNESS: getBranches() returns the waiting branches. We want all the branches in the event, so that
		// presumes there are no branches answered yet. We also presume all branches have been added by now.
		auto& event = getEvent();
		event.writeLog(make_shared<CallStartedEventLog>(*event.getMsgSip()->getSip(), getBranches()));
	}

	ForkContextBase::start();
}

std::shared_ptr<BranchInfo> ForkCallContext::tryToSendFinalResponse() {
	const auto hasBeenForwarded = mCallForwardingBranch.lock() != nullptr;
	if (!callForwardingEnabled() || hasBeenForwarded || (!mIncoming && !mCfg->mForkLate)) {
		tryToSetFinished();
		if (!mIncoming && !mCfg->mForkLate) return nullptr;
	}
	if (!allBranchesAnswered(FinalStatusMode::RFC)) return nullptr;

	auto branch = findBestBranch(mCfg->mForkLate);
	// If a call is canceled by caller/callee, even if some branches only answered 503 or 408, even in fork-late
	// mode, we want to directly send a response.
	if (mCancelled && branch == nullptr) branch = findBestBranch(false);
	if (branch == nullptr) return nullptr;

	if (!callForwardingEnabled()) {
		if (branch->sendResponse(mIncoming != nullptr)) return branch;
		return nullptr;
	}

	// From now on, we will try to forward the call to the voicemail server.
	// Manage several cases before actually trying to forward the call.

	// -- First case: If the 'call-fork-timeout' timer triggered, but the call forwarding did not work: answer '408'
	//                (we know it did not work because this part of the code is reached).
	if (hasBeenForwarded && mLateTimer.hasAlreadyExpiredOnce() && !mFinished) {
		if (branch == mCallForwardingBranch.lock() || allBranchesAnswered(FinalStatusMode::RFC)) {
			sendCustomResponse(SIP_408_REQUEST_TIMEOUT);
			ForkContextBase::setFinished();
			return branch;
		}
	}

	if (hasBeenForwarded) {
		// -- Second case: If we received a final response on all branches, but the call forwarding did not work: answer
		//                 the best response to the caller (we know it did not work because this part of the code is
		//                 reached).
		if (allBranchesAnswered(FinalStatusMode::RFC) && branch->sendResponse(mIncoming != nullptr)) return branch;
		// -- Third case: if the call has already been forwarded, do not forward it again.
		return nullptr;
	}

	// -- Fourth case: make sure the status code received on this branch is supported for call forwarding.
	const auto status = branch->getStatus();
	const auto config = static_pointer_cast<ForkCallContextConfig>(mCfg);
	const auto supported = config->mStatusCodes;
	if (find(supported.cbegin(), supported.cend(), status) == supported.cend()) {
		if (branch->sendResponse(mIncoming != nullptr)) return branch;
		return nullptr;
	}

	// Finally, try to forward the call.
	if (forward(branch->getStatus())) return nullptr;

	// If it failed, try to send the response anyway.
	if (branch->sendResponse(mIncoming != nullptr)) return branch;
	return nullptr;
}

std::shared_ptr<BranchInfo> ForkCallContext::forward(int code) {
	const auto listener = mForkContextListener.lock();
	if (listener == nullptr) {
		LOGE << "Failed to trigger call forwarding (ForkContextListener pointer is empty)";
		return nullptr;
	}
	if (!mIncoming) {
		LOGE << "Failed to trigger call forwarding (incoming request pointer is empty)";
		return nullptr;
	}

	LOGD << "Starting call forwarding with status '" << code << "'";

	const auto request = mIncoming->getIncomingRequest();
	auto* home = request->getHome();
	const auto* sip = request->getSip();

	const auto voicemailServerUri = static_pointer_cast<ForkCallContextConfig>(mCfg)->mVoicemailServerUri;
	const auto target = uri_utils::escape(url_as_string(home, sip->sip_to->a_url), uri_utils::sipUriParamValueReserved);
	const auto cause = to_string(code);
	const auto requestUri = voicemailServerUri.replaceParameter("target", target).replaceParameter("cause", cause);

	const auto requestEvent = RequestSipEvent::makeRestored(mIncoming, request, std::weak_ptr<Module>{});
	if (requestEvent == nullptr) {
		LOGW << "Failed to restore the RequestSipEvent, cannot proceed further: aborting";
		return nullptr;
	}

	const auto contact = make_shared<ExtendedContact>(requestUri, "", "");
	contact->mKey = ContactKey{}.str();
	if (const auto branch = listener->onDispatchNeeded(shared_from_this(), contact)) {
		// Reply to incoming transaction.
		requestEvent->reply(SIP_181_CALL_IS_BEING_FORWARDED, TAG_END());
		mCallForwardingBranch = branch;
		return branch;
	}

	return nullptr;
}

const char* ForkCallContext::getClassName() const {
	return kClassName.data();
}

bool ForkCallContext::shouldFinish() {
	return !mCfg->mForkLate;
}

} // namespace flexisip