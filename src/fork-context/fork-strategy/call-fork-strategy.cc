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

#include "call-fork-strategy.hh"

#include "sofia-sip/sip_status.h"

#include "eventlogs/events/calls/call-ringing-event-log.hh"
#include "eventlogs/events/calls/call-started-event-log.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/fork-status.hh"
#include "fork-context/fork.hh"
#include "registrar/extended-contact.hh"
#include "urgent-codes.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace string_view_literals;

namespace flexisip {

CallForkStrategy::CallForkStrategy(RequestSipEvent& event,
                                   const std::shared_ptr<ForkContextConfig>& config,
                                   CallStep callStep)
    : mCfg(config), mCallStep(callStep), mLogPrefix{LogManager::makeLogPrefixForInstance(this, "CallForkStrategy")} {
	// Deactivate CallLog for diverted call until it is supported
	if (mCallStep == CallStep::Initial) mLog = event.getEventLog<CallLog>();
	LOGD << "New instance";
}

CallForkStrategy::~CallForkStrategy() {
	LOGD << "Destroy instance";
}

std::shared_ptr<const EventLogWriteDispatcher>
CallForkStrategy::makeStartEventLog(const MsgSip& msgSip, const std::list<std::shared_ptr<BranchInfo>>& branches) {
	if (mCallStep == CallStep::Diverted) return {};
	return make_shared<CallStartedEventLog>(*msgSip.getSip(), branches);
}

void CallForkStrategy::cancelWithMessage(const sip_t* received_cancel) {
	if (!mCancel.has_value() && received_cancel && received_cancel->sip_reason)
		mCancel = make_optional<CancelInfo>(sip_reason_dup(mHome.home(), received_cancel->sip_reason));
	else cancelWithStatus(ForkStatus::Standard);
}

void CallForkStrategy::cancelWithStatus(ForkStatus status) {
	if (!mCancel.has_value()) mCancel = make_optional<CancelInfo>(mHome, status);
}

const int* CallForkStrategy::getUrgentCodes() const {
	if (mCfg->mTreatAllErrorsAsUrgent) return kAllCodesUrgent;
	if (mCfg->mTreatDeclineAsUrgent) return kUrgentCodes;
	return kUrgentCodesWithout603;
}

OnResponseAction CallForkStrategy::chooseActionOnResponse(const shared_ptr<BranchInfo>& br) {
	const auto code = br->getStatus();
	if (code >= 300) {
		/*
		 * In fork-late mode, we must not consider that 503 and 408 response codes (which are sent by sofia in case
		 * of i/o error or timeouts) are branches that are answered. Instead, we must wait for the duration of the
		 * fork for new registers.
		 */
		if (code >= 600) {
			// 6xx responses are normally processed as global failures.
			if (!mCfg->mForkNoGlobalDecline) {
				mCancelled = true;
				cancelWithStatus(ForkStatus::DeclinedElsewhere);
			}
			return OnResponseAction::WaitAndUpdate;
		}
		if (isUrgent(code, getUrgentCodes())) {
			if (mUrgentCode == UrgentCodeState::SendOnReceived) {
				mCancelled = true;
				cancelWithStatus(ForkStatus::Standard);
				return OnResponseAction::SendAndUpdate;
			}
			mUrgentCode = UrgentCodeState::AwaitingBetterResponse;
		}
		return OnResponseAction::WaitAndUpdate;
	}
	if (code >= 200) {
		mCancelled = true;
		cancelWithStatus(ForkStatus::AcceptedElsewhere);
		return OnResponseAction::SendAndUpdate;
	}
	if (code > 100 && !mCancelled) {
		return OnResponseAction::SendAndUpdate;
	}
	return OnResponseAction::WaitAndUpdate;
}

ResponseStrategy CallForkStrategy::chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>& best) {
	if (best == nullptr) return ResponseStrategy::Wait;

	// If it failed, try to send the response anyway.
	return ResponseStrategy::Best;
}

ResponseStrategy CallForkStrategy::chooseStrategyOnDecisionTimer() {
	if (mUrgentCode == UrgentCodeState::AwaitingBetterResponse) return ResponseStrategy::Best;
	mUrgentCode = UrgentCodeState::SendOnReceived;
	return ResponseStrategy::Wait;
}

ResponseStrategy CallForkStrategy::chooseStrategyOnLateTimeout() {
	// Cancel all possibly pending outgoing transactions.
	mStopping = true;
	cancelWithStatus(ForkStatus::Standard);

	return ResponseStrategy::BestElseDefault;
}

std::pair<int, const char*> CallForkStrategy::getDefaultResponse() const {
	return {SIP_408_REQUEST_TIMEOUT};
}

void CallForkStrategy::logResponse(const shared_ptr<BranchInfo>& br, RequestSipEvent& request, ResponseSipEvent&) {
	if (mCallStep == CallStep::Diverted) return;

	if (br->getStatus() == 180) {
		request.writeLog(make_shared<CallRingingEventLog>(*request.getSip(), br.get()));
	}
}

void CallForkStrategy::logSentResponse(const std::unique_ptr<ResponseSipEvent>& repEv,
                                       const BranchInfo* branch,
                                       RequestSipEvent&) const {
	if (mCallStep == CallStep::Diverted) return;

	if (repEv == nullptr || !mLog) return;

	if (branch) mLog->setDevice(*branch->getContact());

	const auto* sip = repEv->getMsgSip()->getSip();
	mLog->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);

	if (sip->sip_status->st_status >= 200) mLog->setCompleted();

	repEv->setEventLog(mLog);
}

void CallForkStrategy::updateBranch(const shared_ptr<BranchInfo>& br, RequestSipEvent& request) {
	if (!mCancel || !br->needsDelivery()) return;

	br->cancel(mCancel, !mStopping);
	// Always notify here, even if the branch is not canceled (due to status or iOS devices specific reasons).
	br->notifyBranchCanceled(mCancel->mStatus);

	if (mCallStep == CallStep::Diverted) return;

	auto eventLog = make_shared<CallLog>(request.getSip());
	eventLog->setDevice(*br->getContact());
	eventLog->setCancelled();
	eventLog->setForkStatus(mCancel->mStatus);
	request.writeLog(eventLog);
}

bool CallForkStrategy::shouldAcceptNextBranches() const {
	return !isCompleted();
}

bool CallForkStrategy::mayAcceptNewRegister(const SipUri&,
                                            const std::string&,
                                            const std::shared_ptr<ExtendedContact>&) {
	LOGD << "Received new registration notification";
	return !isCompleted() || mCfg->mForkLate;
}

bool CallForkStrategy::shouldAcceptDispatch(const std::shared_ptr<BranchInfo>& branch, const std::string&) {
	return !isCompleted() || (branch && branch->pushContextIsAppleVoIp());
}

void CallForkStrategy::onDispatch(const std::shared_ptr<BranchInfo>& dispatchedBranch) {
	if (mCancelled) {
		dispatchedBranch->cancel(mCancel);
	}
}

bool CallForkStrategy::isCompleted() const {
	return mCancelled;
}

void CallForkStrategy::onInternalError() {
	cancelWithStatus(ForkStatus::Standard);
}

void CallForkStrategy::onCancel(const MsgSip& ms) {
	LOGD << "Canceling fork";
	if (mLog) {
		mLog->setCancelled();
		mLog->setCompleted();
	}
	mCancelled = true;
	cancelWithMessage(ms.getSip());
}
} // namespace flexisip