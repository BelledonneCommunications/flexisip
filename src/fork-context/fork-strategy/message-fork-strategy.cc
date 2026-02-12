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

#include "message-fork-strategy.hh"

#include "eventlogs/events/event-id.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/events/messages/message-response-from-recipient-event-log.hh"
#include "eventlogs/events/messages/message-sent-event-log.hh"
#include "flexisip/utils/sip-uri.hh"
#include "fork-context/message-kind.hh"
#include "modules/module-toolbox.hh"
#include "registrar/extended-contact.hh"
#include "sofia-sip/sip.h"
#include "sofia-sip/sip_protos.h"
#include "sofia-sip/sip_status.h"
#include "sofia-wrapper/sip-header-private.hh"
#include "urgent-codes.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {

MessageForkStrategy::MessageForkStrategy(const MessageKind& kind,
                                         bool isRestored,
                                         const std::shared_ptr<ForkContextConfig>& config)
    : mKind(kind), mCfg(config), mLogPrefix(LogManager::makeLogPrefixForInstance(this, "MessageForkStrategy")) {
	LOGD << "New instance";
	if (!isRestored) {
		if (mCfg->mForkLate && mCfg->mDeliveryTimeout > 30s) {
			mExpirationDate = system_clock::to_time_t(system_clock::now() + mCfg->mDeliveryTimeout);
		}
		mDeliveredCount = 0;
	}
}

MessageForkStrategy::~MessageForkStrategy() {
	LOGD << "Destroy instance";
}

std::shared_ptr<const EventLogWriteDispatcher>
MessageForkStrategy::makeStartEventLog(const MsgSip& msgSip, const std::list<std::shared_ptr<BranchInfo>>& branches) {
	return make_shared<MessageSentEventLog>(*msgSip.getSip(), branches, mKind);
}

void MessageForkStrategy::logResponseFromRecipient(const BranchInfo& branch, ResponseSipEvent& respEv) {
	const auto* sip = respEv.getMsgSip()->getSip();
	const auto& sipRequest = *branch.getRequestMsg()->getSip();
	const auto forwardedId = ModuleToolbox::getCustomHeaderByName(&sipRequest, kEventIdHeader.data());

	try {
		const auto log = make_shared<MessageResponseFromRecipientEventLog>(
		    sipRequest, *branch.getContact(), mKind,
		    forwardedId ? std::optional<EventId>(forwardedId->un_value) : std::nullopt);

		log->setDestination(sipRequest.sip_request->rq_url);
		log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);

		if (sipRequest.sip_priority && sipRequest.sip_priority->g_string)
			log->setPriority(sipRequest.sip_priority->g_string);

		log->setCompleted();
		respEv.writeLog(log);
	} catch (const exception& e) {
		LOGE << "Failed to write event log response from recipient: " << e.what();
	}
}

OnResponseAction MessageForkStrategy::chooseActionOnResponse(const shared_ptr<BranchInfo>& br) {
	const auto code = br->getStatus();

	if (code > 100 && code < 300) {
		if (code >= 200) ++mDeliveredCount;
		return OnResponseAction::Send;
	}
	if (code >= 300 && !mCfg->mForkLate && isUrgent(code, kUrgentCodes)) {
		// Expedite back any urgent replies if late forking is disabled.
		return OnResponseAction::Send;
	}
	return OnResponseAction::Wait;
}

ResponseStrategy MessageForkStrategy::chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>&) {
	return ResponseStrategy::Default;
}

ResponseStrategy MessageForkStrategy::chooseStrategyOnDecisionTimer() {
	return ResponseStrategy::Default;
}

ResponseStrategy MessageForkStrategy::chooseStrategyOnLateTimeout() {
	return ResponseStrategy::BestElseDefault;
}

std::pair<int, const char*> MessageForkStrategy::getDefaultResponse() const {
	return {SIP_202_ACCEPTED};
}

void MessageForkStrategy::logResponse(const shared_ptr<BranchInfo>& br, RequestSipEvent&, ResponseSipEvent& response) {
	logResponseFromRecipient(*br, response);
}

void MessageForkStrategy::logSentResponse(const std::unique_ptr<ResponseSipEvent>& respEv,
                                          const BranchInfo*,
                                          RequestSipEvent& reqEv) const {
	if (mDeliveredCount != 1) return;

	// In the sender's log will appear the status code from the receiver.
	const auto* sip = respEv->getMsgSip()->getSip();
	const auto* sipRequest = reqEv.getSip();
	const auto log = make_shared<MessageLog>(*sip);

	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	if (sipRequest->sip_priority && sipRequest->sip_priority->g_string)
		log->setPriority(sipRequest->sip_priority->g_string);

	log->setCompleted();
	respEv->writeLog(log);
}

bool MessageForkStrategy::shouldAcceptNextBranches() const {
	return true;
}

bool MessageForkStrategy::mayAcceptNewRegister(const SipUri&,
                                               const std::string&,
                                               const std::shared_ptr<ExtendedContact>&) {
	return true;
}

bool MessageForkStrategy::shouldAcceptDispatch(const shared_ptr<BranchInfo>& br, const std::string& uid) {
	if (!uid.empty()) {
		if (br == nullptr) {
			LOGD << "This is a new client instance (the message needs to be delivered)";
			return true;
		} else if (br->needsDelivery(FinalStatusMode::ForkLate)) {
			// This is a client for which the message was not delivered yet (or failed to be delivered).
			// The message needs to be delivered.
			LOGD << "This client is reconnecting but message was not delivered before";
			return true;
		}
	}

	// In all other cases we can accept a new transaction only if the message has not been delivered already.
	LOGD << "Message has been delivered " << mDeliveredCount << " times";
	if (mDeliveredCount == 0) return true;

	return false;
}

void MessageForkStrategy::onNewBranch(const shared_ptr<BranchInfo>& br) {
	if (mKind.getCardinality() == MessageKind::Cardinality::ToConferenceServer) {
		// Pass event ID to the conference server to get it back when it dispatches the message to the intended
		// recipients. As of 2023-06-29, we do not expect to have more branches added after the initial context creation
		// in this particular case, which means we could move adding this header to the ::start() method (and avoid
		// computing the EventId twice), but we'd better be safe than sorry.
		const auto sipMsg = br->getRequestMsg();
		sipMsg->insertHeader(sofiasip::SipCustomHeader(kEventIdHeader, string(EventId(*sipMsg->getSip()))));
	}
}

void MessageForkStrategy::onCancel(const MsgSip&) {
	LOGE << "Cancel is for INVITE request";
}
} // namespace flexisip