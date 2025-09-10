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

#include "fork-context/fork-message-context.hh"

#include <algorithm>
#include <chrono>
#include <optional>

#include "eventlogs/events/event-id.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/events/messages/message-response-from-recipient-event-log.hh"
#include "eventlogs/events/messages/message-sent-event-log.hh"
#include "flexisip/module.hh"
#include "flexisip/utils/sip-uri.hh"
#include "fork-context/fork-context-base.hh"
#include "fork-context/message-kind.hh"
#include "modules/module-toolbox.hh"
#include "registrar/extended-contact.hh"
#include "sofia-sip/sip.h"
#include "sofia-sip/sip_protos.h"
#include "sofia-sip/sip_status.h"
#include "sofia-wrapper/sip-header-private.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

using namespace std;
using namespace std::chrono;
using namespace flexisip;

ForkMessageContext::ForkMessageContext(std::unique_ptr<RequestSipEvent>&& event,
                                       sofiasip::MsgSipPriority priority,
                                       bool isRestored,
                                       const std::weak_ptr<ForkContextListener>& forkContextListener,
                                       const std::weak_ptr<InjectorListener>& injectorListener,
                                       AgentInterface* agent,
                                       const std::shared_ptr<ForkContextConfig>& config,
                                       const std::weak_ptr<StatPair>& counter)
    : ForkContextBase{agent,   config,   injectorListener, forkContextListener, std::move(event),
                      counter, priority, isRestored},
      mKind(*ForkContextBase::getEvent().getMsgSip()->getSip(), priority),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "ForkMessageContext")) {
	LOGD << "New instance";
	if (!isRestored) {
		// Start the acceptance timer immediately.
		if (mCfg->mForkLate && mCfg->mDeliveryTimeout > 30s) {
			mExpirationDate = system_clock::to_time_t(system_clock::now() + mCfg->mDeliveryTimeout);
			mAcceptanceTimer = make_unique<sofiasip::Timer>(mAgent->getRoot(), mCfg->mUrgentTimeout);
			mAcceptanceTimer->set([this]() { onAcceptanceTimer(); });
		}
		mDeliveredCount = 0;
	}
}

std::shared_ptr<ForkMessageContext>
ForkMessageContext::restore(ForkMessageContextDb& forkContextFromDb,
                            const std::weak_ptr<ForkContextListener>& forkContextListener,
                            const std::weak_ptr<InjectorListener>& injectorListener,
                            Agent* agent,
                            const std::shared_ptr<ForkContextConfig>& config,
                            const std::weak_ptr<StatPair>& counter) {
	const auto context = make(
	    [&agent, &forkContextFromDb] {
		    const auto router = agent->findModuleByRole("Router");
		    const auto msg = make_shared<MsgSip>(0, forkContextFromDb.request);
		    return RequestSipEvent::makeRestored(agent->getIncomingAgent(), msg, router);
	    }(),
	    forkContextFromDb.msgPriority, true, forkContextListener, injectorListener, agent, config, counter);

	context->mFinished = forkContextFromDb.isFinished;
	context->mDeliveredCount = forkContextFromDb.deliveredCount;
	context->mCurrentPriority = forkContextFromDb.currentPriority;
	context->mExpirationDate = timegm(&forkContextFromDb.expirationDate);

	auto timeLeftUntilExpiration = system_clock::from_time_t(context->mExpirationDate) - system_clock::now();
	if (timeLeftUntilExpiration < 0s) timeLeftUntilExpiration = 0s;
	context->mLateTimer.set(
	    [forkMessageContext = weak_ptr<ForkMessageContext>{context}]() {
		    if (const auto context = forkMessageContext.lock()) context->processLateTimeout();
	    },
	    timeLeftUntilExpiration);

	for (const auto& dbKey : forkContextFromDb.dbKeys)
		context->addKey(dbKey);

	for (const auto& dbBranch : forkContextFromDb.dbBranches)
		context->restoreBranch(dbBranch);

	return context;
}

ForkMessageContext::~ForkMessageContext() {
	LOGD << "Destroy instance";
}

bool ForkMessageContext::shouldFinish() {
	// The messaging fork context controls its termination in late forking mode.
	return !mCfg->mForkLate;
}

void ForkMessageContext::logResponseFromRecipient(const BranchInfo& branch, ResponseSipEvent& respEv) {
	if (mKind.getKind() == MessageKind::Kind::Refer) return;

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

void ForkMessageContext::logResponseToSender(const RequestSipEvent& reqEv, ResponseSipEvent& respEv) const {
	if (mKind.getKind() == MessageKind::Kind::Refer) return;

	const auto* sip = respEv.getMsgSip()->getSip();
	const auto* sipRequest = reqEv.getMsgSip()->getSip();
	const auto log = make_shared<MessageLog>(*sip);

	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	if (sipRequest->sip_priority && sipRequest->sip_priority->g_string)
		log->setPriority(sipRequest->sip_priority->g_string);

	log->setCompleted();
	respEv.writeLog(log);
}

void ForkMessageContext::onResponse(const shared_ptr<BranchInfo>& br, ResponseSipEvent& event) {
	ForkContextBase::onResponse(br, event);

	const auto code = event.getMsgSip()->getSip()->sip_status->st_status;
	LOGD << "Executing " << __func__;

	if (code > 100 && code < 300) {
		if (code >= 200) {
			mDeliveredCount++;
			if (mAcceptanceTimer) {
				if (mIncoming)
					// In the sender's log will appear the status code from the receiver.
					logResponseToSender(getEvent(), event);

				mAcceptanceTimer.reset(nullptr);
			}
		}
		logResponseFromRecipient(*br, event);
		br->forwardResponse(mIncoming != nullptr);
	} else if (code >= 300 && !mCfg->mForkLate && isUrgent(code, kUrgentCodes)) {
		// Expedite back any urgent replies if late forking is disabled.
		logResponseFromRecipient(*br, event);
		br->forwardResponse(mIncoming != nullptr);
	} else {
		logResponseFromRecipient(*br, event);
	}
	checkFinished();
	if (mAcceptanceTimer && allBranchesAnswered(FinalStatusMode::RFC) && !isFinished()) {
		// If all branches are answered quickly but the ForkContext is not finished and the mAcceptanceTimer is still up
		// we can trigger it directly.
		onAcceptanceTimer();
	}
}

void ForkMessageContext::acceptMessage() {
	// We are called here if no good response has been received from any branch, in fork-late mode only.
	if (mIncoming == nullptr) return;

	// In fork late mode, never answer a service unavailable.
	shared_ptr<MsgSip> msgSip(mIncoming->createResponse(SIP_202_ACCEPTED));
	auto ev = make_unique<ResponseSipEvent>(ResponseSipEvent(mAgent->getOutgoingAgent(), msgSip));
	ev = ForkContextBase::onForwardResponse(std::move(ev));

	// In the sender's log will appear the 202 accepted from Flexisip server.
	logResponseToSender(getEvent(), *ev);
}

void ForkMessageContext::onAcceptanceTimer() {
	LOGD << "Executing " << __func__;
	acceptMessage();
	mAcceptanceTimer.reset(nullptr);
}

void ForkMessageContext::onNewBranch(const shared_ptr<BranchInfo>& br) {
	if (!br->getUid().empty()) {
		// Check for a branch that may already exist with this UID, and eventually clean it up.
		if (const auto tmp = findBranchByUid(br->getUid())) removeBranch(tmp);
	} else {
		LOGD << "Fork error: no unique id found for contact '" << br->getContact()->urlAsString() << "'";
	}

	if (mKind.getCardinality() == MessageKind::Cardinality::ToConferenceServer) {
		// Pass event ID to the conference server to get it back when it dispatches the message to the intended
		// recipients. As of 2023-06-29, we do not expect to have more branches added after the initial context creation
		// in this particular case, which means we could move adding this header to the ::start() method (and avoid
		// computing the EventId twice), but we'd better be safe than sorry.
		const auto sipMsg = br->getRequestMsg();
		sipMsg->insertHeader(sofiasip::SipCustomHeader(kEventIdHeader, string(EventId(*sipMsg->getSip()))));
	}
}

void ForkMessageContext::onNewRegister(const SipUri& dest,
                                       const std::string& uid,
                                       const std::shared_ptr<ExtendedContact>& newContact) {
	const auto forkContextListener = mForkContextListener.lock();
	if (!forkContextListener) {
		LOGE << "ForkContextListener is missing, cannot process new register (this should not happen)";
		return;
	}

	if (const auto [status, _] = shouldDispatch(dest, uid); status != DispatchStatus::DispatchNeeded) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, status);
		return;
	}

	if (!uid.empty()) {
		if (const auto br = findBranchByUid(uid); br == nullptr) {
			LOGD << "This is a new client instance (the message needs to be delivered)";
			forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
			return;
		} else if (br->needsDelivery(FinalStatusMode::ForkLate)) {
			// This is a client for which the message was not delivered yet (or failed to be delivered).
			// The message needs to be delivered.
			LOGD << "This client is reconnecting but message was not delivered before";
			forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
			return;
		}
	}

	// In all other cases we can accept a new transaction only if the message has not been delivered already.
	LOGD << "Message has been delivered " << mDeliveredCount << " times";

	if (mDeliveredCount == 0) {
		forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
		return;
	}

	forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
	                                                   DispatchStatus::DispatchNotNeeded);
}

ForkMessageContextDb ForkMessageContext::getDbObject() {
	ForkMessageContextDb dbObject{};
	dbObject.isMessage = mKind.getKind() == MessageKind::Kind::Message;
	dbObject.isFinished = mFinished;
	dbObject.msgPriority = mMsgPriority;
	dbObject.deliveredCount = mDeliveredCount;
	dbObject.currentPriority = mCurrentPriority;
	dbObject.expirationDate = *gmtime(&mExpirationDate);
	dbObject.request = getEvent().getMsgSip()->msgAsString();
	dbObject.dbKeys.insert(dbObject.dbKeys.end(), mKeys.begin(), mKeys.end());

	for (const auto& waitingBranch : mWaitingBranches)
		dbObject.dbBranches.push_back(waitingBranch->getDbObject());

	return dbObject;
}

void ForkMessageContext::restoreBranch(const BranchInfoDb& dbBranch) {
	mWaitingBranches.push_back(BranchInfo::make(shared_from_this(), dbBranch, mAgent));
}

void ForkMessageContext::start() {
	// A priority of -1 means "first start".
	if (mCurrentPriority == -1.f /* first start */ && mKind.getKind() != MessageKind::Kind::Refer) {
		// SOUNDNESS: getBranches() returns the waiting branches. We want all the branches in the event, so that
		// presumes there are no branches answered yet. We also presume all branches have been added by now.
		auto& event = getEvent();
		const auto& branches = getBranches();
		const auto eventLog = make_shared<MessageSentEventLog>(*event.getMsgSip()->getSip(), branches, mKind);
		event.writeLog(eventLog);
	}

	ForkContextBase::start();
}

const char* ForkMessageContext::getClassName() const {
	return kClassName.data();
}

#ifdef ENABLE_UNIT_TESTS
void ForkMessageContext::assertEqual(const shared_ptr<ForkMessageContext>& expected) {
	BC_ASSERT_EQUAL(int(mKind.getKind()), int(expected->mKind.getKind()), int, "%d");
	BC_ASSERT_EQUAL(mFinished, expected->mFinished, bool, "%d");
	BC_ASSERT_EQUAL(int(mMsgPriority), int(expected->mMsgPriority), int, "%i");
	BC_ASSERT_EQUAL(mDeliveredCount, expected->mDeliveredCount, int, "%d");
	BC_ASSERT_EQUAL(mCurrentPriority, expected->mCurrentPriority, float, "%f");
	BC_ASSERT_EQUAL(mExpirationDate, expected->mExpirationDate, time_t, "%ld");
	BC_ASSERT_TRUE(getEvent().getMsgSip()->msgAsString() == expected->getEvent().getMsgSip()->msgAsString());

	if (mKeys.size() == expected->mKeys.size()) {
		sort(mKeys.begin(), mKeys.end());
		sort(expected->mKeys.begin(), expected->mKeys.end());
		BC_ASSERT_TRUE(mKeys == expected->mKeys);
	} else {
		BC_FAIL("Keys list is not the same size");
	}

	if (mWaitingBranches.size() == expected->mWaitingBranches.size()) {
		mWaitingBranches.sort([](const auto& a, const auto& b) { return a->getUid() < b->getUid(); });
		expected->mWaitingBranches.sort([](const auto& a, const auto& b) { return a->getUid() < b->getUid(); });
		std::ignore = equal(mWaitingBranches.begin(), mWaitingBranches.end(), expected->mWaitingBranches.begin(),
		                    [](const auto& a, const auto& b) {
			                    a->assertEqual(b);
			                    return true;
		                    });
	} else {
		BC_FAIL("Waiting branch list is not the same size");
	}
}
#endif