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
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_status.h>

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

#include "eventlogs/events/event-id.hh"
#include "eventlogs/events/eventlogs.hh"
#include "eventlogs/events/messages/message-response-from-recipient-event-log.hh"
#include "eventlogs/events/messages/message-sent-event-log.hh"
#include "flexisip/common.hh"
#include "flexisip/module.hh"
#include "flexisip/utils/sip-uri.hh"
#include "fork-context/fork-context-base.hh"
#include "fork-context/message-kind.hh"
#include "module-toolbox.hh"
#include "registrar/extended-contact.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/string-utils.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

shared_ptr<ForkMessageContext> ForkMessageContext::make(const std::shared_ptr<ModuleRouter>& router,
                                                        const std::weak_ptr<ForkContextListener>& listener,
                                                        std::unique_ptr<RequestSipEvent>&& event,
                                                        sofiasip::MsgSipPriority priority) {
	return std::shared_ptr<ForkMessageContext>(new ForkMessageContext(router, listener, std::move(event), priority));
}

shared_ptr<ForkMessageContext> ForkMessageContext::make(const std::shared_ptr<ModuleRouter> router,
                                                        const std::weak_ptr<ForkContextListener>& listener,
                                                        ForkMessageContextDb& forkFromDb) {
	auto msgSipFromDB = make_shared<MsgSip>(0, forkFromDb.request);
	auto requestSipEventFromDb = RequestSipEvent::makeRestored(router->getAgent()->shared_from_this(), msgSipFromDB,
	                                                           router->getAgent()->findModule("Router"));

	// new because make_shared require a public constructor.
	shared_ptr<ForkMessageContext> shared{
	    new ForkMessageContext(router, listener, std::move(requestSipEventFromDb), forkFromDb.msgPriority, true)};
	shared->mFinished = forkFromDb.isFinished;
	shared->mDeliveredCount = forkFromDb.deliveredCount;
	shared->mCurrentPriority = forkFromDb.currentPriority;

	shared->mExpirationDate = timegm(&forkFromDb.expirationDate);
	auto diff = system_clock::from_time_t(shared->mExpirationDate) - system_clock::now();
	if (diff < 0s) diff = 0s;
	shared->mLateTimer.set(
	    [weak = weak_ptr<ForkMessageContext>{shared}]() {
		    if (auto sharedPtr = weak.lock()) {
			    sharedPtr->processLateTimeout();
		    }
	    },
	    diff);

	for (const auto& dbKey : forkFromDb.dbKeys) {
		shared->addKey(dbKey);
	}

	for (const auto& dbBranch : forkFromDb.dbBranches) {
		shared->restoreBranch(dbBranch);
	}

	return shared;
}

ForkMessageContext::ForkMessageContext(const std::shared_ptr<ModuleRouter>& router,
                                       const std::weak_ptr<ForkContextListener>& listener,
                                       std::unique_ptr<RequestSipEvent>&& event,
                                       sofiasip::MsgSipPriority msgPriority,
                                       bool isRestored)
    : ForkContextBase(router,
                      router->getAgent(),
                      router->getMessageForkCfg(),
                      listener,
                      std::move(event),
                      router->mStats.mCountMessageForks,
                      msgPriority,
                      isRestored),
      mKind(*getEvent().getMsgSip()->getSip(), msgPriority),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "ForkMessageContext")) {
	LOGD << "New instance";
	if (!isRestored) {
		// Start the acceptance timer immediately.
		if (mCfg->mForkLate && mCfg->mDeliveryTimeout > 30) {
			mExpirationDate = system_clock::to_time_t(system_clock::now() + chrono::seconds(mCfg->mDeliveryTimeout));

			mAcceptanceTimer = make_unique<sofiasip::Timer>(mAgent->getRoot(), mCfg->mUrgentTimeout);
			mAcceptanceTimer->set([this]() { onAcceptanceTimer(); });
		}
		mDeliveredCount = 0;
	}
}

ForkMessageContext::~ForkMessageContext() {
	LOGD << "Destroy instance";
}

bool ForkMessageContext::shouldFinish() {
	return !mCfg->mForkLate; // the messaging fork context controls its termination in late forking mode.
}

void ForkMessageContext::logResponseFromRecipient(const BranchInfo& branch, ResponseSipEvent& respEv) {
	if (mKind.getKind() == MessageKind::Kind::Refer) return;

	const sip_t& sipRequest = *branch.mRequestMsg->getSip();
	const sip_t* sip = respEv.getMsgSip()->getSip();
	const auto forwardedId = ModuleToolbox::getCustomHeaderByName(&sipRequest, kEventIdHeader);

	try {
		auto log = make_shared<MessageResponseFromRecipientEventLog>(
		    sipRequest, *branch.mContact, mKind,
		    forwardedId ? std::optional<EventId>(forwardedId->un_value) : std::nullopt);
		log->setDestination(sipRequest.sip_request->rq_url);
		log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
		if (sipRequest.sip_priority && sipRequest.sip_priority->g_string) {
			log->setPriority(sipRequest.sip_priority->g_string);
		}
		log->setCompleted();
		respEv.writeLog(log);
	} catch (const exception& e) {
		LOGE << "Could not log response from recipient: " << e.what();
	}
}

void ForkMessageContext::logResponseToSender(const RequestSipEvent& reqEv, ResponseSipEvent& respEv) {
	if (mKind.getKind() == MessageKind::Kind::Refer) return;

	const sip_t* sipRequest = reqEv.getMsgSip()->getSip();
	const sip_t* sip = respEv.getMsgSip()->getSip();
	auto log = make_shared<MessageLog>(*sip);
	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	if (sipRequest->sip_priority && sipRequest->sip_priority->g_string) {
		log->setPriority(sipRequest->sip_priority->g_string);
	}
	log->setCompleted();
	respEv.writeLog(log);
}

void ForkMessageContext::onResponse(const shared_ptr<BranchInfo>& br, ResponseSipEvent& event) {
	ForkContextBase::onResponse(br, event);

	const auto code = event.getMsgSip()->getSip()->sip_status->st_status;
	LOGD << "Running " << __func__;

	if (code > 100 && code < 300) {
		if (code >= 200) {
			mDeliveredCount++;
			if (mAcceptanceTimer) {
				if (mIncoming)
					// in the sender's log will appear the status code from the receiver
					logResponseToSender(getEvent(), event);

				mAcceptanceTimer.reset(nullptr);
			}
		}
		logResponseFromRecipient(*br, event);
		forwardResponse(br);
	} else if (code >= 300 && !mCfg->mForkLate && isUrgent(code, sUrgentCodes)) {
		/*expedite back any urgent replies if late forking is disabled */
		logResponseFromRecipient(*br, event);
		forwardResponse(br);
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

/*we are called here if no good response has been received from any branch, in fork-late mode only */
void ForkMessageContext::acceptMessage() {
	if (mIncoming == nullptr) return;

	/*in fork late mode, never answer a service unavailable*/
	shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_202_ACCEPTED));
	auto ev = make_unique<ResponseSipEvent>(ResponseSipEvent(mAgent->getOutgoingAgent(), msgsip));
	ev = forwardResponse(std::move(ev));

	// in the sender's log will appear the 202 accepted from Flexisip server
	logResponseToSender(getEvent(), *ev);
}

void ForkMessageContext::onAcceptanceTimer() {
	LOGD << "Running " << __func__;
	acceptMessage();
	mAcceptanceTimer.reset(nullptr);
}

void ForkMessageContext::onNewBranch(const shared_ptr<BranchInfo>& br) {
	if (br->mUid.size() > 0) {
		/*check for a branch already existing with this uid, and eventually clean it*/
		shared_ptr<BranchInfo> tmp = findBranchByUid(br->mUid);
		if (tmp) {
			removeBranch(tmp);
		}
	} else {
		LOGD << "Fork error: no unique id found for contact";
	}
	if (mKind.getCardinality() == MessageKind::Cardinality::ToConferenceServer) {
		// Pass event ID to the conference server to get it back when it dispatches the message to the intended
		// recipients. As of 2023-06-29, we do not expect to have more branches added after the initial context creation
		// in this particular case, which means we could move adding this header to the ::start() method (and avoid
		// computing the EventId twice), but we'd better be safe than sorry.
		const auto sipMsg = br->mRequestMsg;
		sipMsg->insertHeader(sofiasip::SipCustomHeader(kEventIdHeader, string(EventId(*sipMsg->getSip()))));
	}
}

void ForkMessageContext::onNewRegister(const SipUri& dest,
                                       const std::string& uid,
                                       const std::shared_ptr<ExtendedContact>& newContact) {
	LOGD << "Running " << __func__;
	const auto& sharedListener = mListener.lock();
	if (!sharedListener) {
		LOGE << "Listener missing, this should not happened";
		return;
	}

	const auto dispatchPair = shouldDispatch(dest, uid);
	if (dispatchPair.first != DispatchStatus::DispatchNeeded) {
		sharedListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, dispatchPair.first);
		return;
	}

	if (uid.size() > 0) {
		shared_ptr<BranchInfo> br = findBranchByUid(uid);
		if (br == nullptr) {
			// this is a new client instance. The message needs
			// to be delivered.
			LOGD << "This is a new client instance";
			sharedListener->onDispatchNeeded(shared_from_this(), newContact);
			return;
		} else if (br->needsDelivery(FinalStatusMode::ForkLate)) {
			// this is a client for which the message wasn't delivered yet (or failed to be delivered). The message
			// needs to be delivered.
			LOGD << "This client is reconnecting but was not delivered before";
			sharedListener->onDispatchNeeded(shared_from_this(), newContact);
			return;
		}
	}
	// in all other case we can accept a new transaction only if the message hasn't been delivered already.
	LOGD << "Message has been delivered " << mDeliveredCount << " times";

	if (mDeliveredCount == 0) {
		sharedListener->onDispatchNeeded(shared_from_this(), newContact);
		return;
	}

	sharedListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
	                                              DispatchStatus::DispatchNotNeeded);
	return;
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
	for (const auto& waitingBranch : mWaitingBranches) {
		dbObject.dbBranches.push_back(waitingBranch->getDbObject());
	}

	return dbObject;
}

void ForkMessageContext::restoreBranch(const BranchInfoDb& dbBranch) {
	mWaitingBranches.push_back(BranchInfo::make(shared_from_this(), dbBranch, mAgent));
}

void ForkMessageContext::start() {
	bool firstStart = mCurrentPriority == -1;
	if (firstStart && mKind.getKind() != MessageKind::Kind::Refer) {
		// SOUNDNESS: getBranches() returns the waiting branches. We want all the branches in the event, so that
		// presumes there are no branches answered yet. We also presume all branches have been added by now.
		const auto& branches = getBranches();
		auto& event = getEvent();
		const auto eventLog = make_shared<MessageSentEventLog>(*event.getMsgSip()->getSip(), branches, mKind);
		event.writeLog(eventLog);
	}

	ForkContextBase::start();
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
		mWaitingBranches.sort([](const auto& a, const auto& b) { return a->mUid < b->mUid; });
		expected->mWaitingBranches.sort([](const auto& a, const auto& b) { return a->mUid < b->mUid; });
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