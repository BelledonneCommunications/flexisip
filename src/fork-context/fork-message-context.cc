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

#include "fork-context/fork-message-context.hh"

#include <algorithm>
#include <chrono>

#include <sofia-sip/sip_status.h>

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

#include "flexisip/common.hh"
#include "eventlogs/events/eventlogs.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

shared_ptr<ForkMessageContext> ForkMessageContext::make(const std::shared_ptr<ModuleRouter>& router,
                                                        const std::shared_ptr<RequestSipEvent>& event,
                                                        const std::weak_ptr<ForkContextListener>& listener,
                                                        sofiasip::MsgSipPriority priority) {
	return std::shared_ptr<ForkMessageContext>(new ForkMessageContext(router, event, listener, priority));
}

shared_ptr<ForkMessageContext> ForkMessageContext::make(const std::shared_ptr<ModuleRouter> router,
                                                        const std::weak_ptr<ForkContextListener>& listener,
                                                        ForkMessageContextDb& forkFromDb) {
	auto msgSipFromDB = make_shared<MsgSip>(0, forkFromDb.request);
	auto requestSipEventFromDb = RequestSipEvent::makeRestored(router->getAgent()->shared_from_this(), msgSipFromDB,
	                                                           router->getAgent()->findModule("Router"));

	// new because make_shared require a public constructor.
	shared_ptr<ForkMessageContext> shared{
	    new ForkMessageContext(router, requestSipEventFromDb, listener, forkFromDb.msgPriority, true)};
	shared->mIsMessage = forkFromDb.isMessage;
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
                                       const std::shared_ptr<RequestSipEvent>& event,
                                       const std::weak_ptr<ForkContextListener>& listener,
                                       sofiasip::MsgSipPriority msgPriority,
                                       bool isRestored)
    : ForkContextBase(router,
                      router->getAgent(),
                      event,
                      router->getMessageForkCfg(),
                      listener,
                      router->mStats.mCountMessageForks,
                      msgPriority,
                      isRestored) {
	LOGD("New ForkMessageContext %p", this);
	if (!isRestored) {
		// Start the acceptance timer immediately.
		if (mCfg->mForkLate && mCfg->mDeliveryTimeout > 30) {
			mExpirationDate = system_clock::to_time_t(system_clock::now() + seconds(mCfg->mDeliveryTimeout));

			mAcceptanceTimer = make_unique<sofiasip::Timer>(mAgent->getRoot(), mCfg->mUrgentTimeout);
			mAcceptanceTimer->set([this]() { onAcceptanceTimer(); });
		}
		mDeliveredCount = 0;
		mIsMessage = event->getMsgSip()->getSip()->sip_request->rq_method == sip_method_message;
	}
}

ForkMessageContext::~ForkMessageContext() {
	LOGD("Destroy ForkMessageContext %p", this);
}

bool ForkMessageContext::shouldFinish() {
	return !mCfg->mForkLate; // the messaging fork context controls its termination in late forking mode.
}

void ForkMessageContext::logDeliveredToUserEvent(const shared_ptr<RequestSipEvent>& reqEv,
                                                 const shared_ptr<ResponseSipEvent>& respEv) {
	sip_t* sip = respEv->getMsgSip()->getSip();
	const sip_t* sipRequest = reqEv->getMsgSip()->getSip();
	auto log = make_shared<MessageLog>(sip, MessageLog::ReportType::DeliveredToUser);
	log->setDestination(sipRequest->sip_request->rq_url);
	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	if (sipRequest->sip_priority && sipRequest->sip_priority->g_string) {
		log->setPriority(sipRequest->sip_priority->g_string);
	}
	log->setCompleted();
	respEv->setEventLog(log);
	respEv->flushLog();
}

void ForkMessageContext::onResponse(const shared_ptr<BranchInfo>& br, const shared_ptr<ResponseSipEvent>& event) {
	ForkContextBase::onResponse(br, event);

	const auto code = event->getMsgSip()->getSip()->sip_status->st_status;
	LOGD("ForkMessageContext[%p]::onResponse()", this);

	if (code > 100 && code < 300) {
		if (code >= 200) {
			mDeliveredCount++;
			if (mAcceptanceTimer) {
				if (mIncoming && mIsMessage)
					logReceivedFromUserEvent(
					    mEvent, event); /*in the sender's log will appear the status code from the receiver*/
				mAcceptanceTimer.reset(nullptr);
			}
		}
		if (mIsMessage) logDeliveredToUserEvent(br->mRequest, event);
		forwardResponse(br);
	} else if (code >= 300 && !mCfg->mForkLate && isUrgent(code, sUrgentCodes)) {
		/*expedite back any urgent replies if late forking is disabled */
		if (mIsMessage) logDeliveredToUserEvent(br->mRequest, event);
		forwardResponse(br);
	} else {
		if (mIsMessage) logDeliveredToUserEvent(br->mRequest, event);
	}
	checkFinished();
	if (mAcceptanceTimer && allBranchesAnswered() && !isFinished()) {
		// If all branches are answered quickly but the ForkContext is not finished and the mAcceptanceTimer is still up
		// we can trigger it directly.
		onAcceptanceTimer();
	}
}

void ForkMessageContext::logReceivedFromUserEvent(const shared_ptr<RequestSipEvent>& reqEv,
                                                  const shared_ptr<ResponseSipEvent>& respEv) {
	sip_t* sip = respEv->getMsgSip()->getSip();
	const sip_t* sipRequest = reqEv->getMsgSip()->getSip();
	auto log = make_shared<MessageLog>(sip, MessageLog::ReportType::ReceivedFromUser);
	log->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
	if (sipRequest->sip_priority && sipRequest->sip_priority->g_string) {
		log->setPriority(sipRequest->sip_priority->g_string);
	}
	log->setCompleted();
	respEv->setEventLog(log);
	respEv->flushLog();
}

/*we are called here if no good response has been received from any branch, in fork-late mode only */
void ForkMessageContext::acceptMessage() {
	if (mIncoming == nullptr) return;

	/*in fork late mode, never answer a service unavailable*/
	shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_202_ACCEPTED));
	shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(mAgent->getOutgoingAgent(), msgsip));
	forwardResponse(ev);
	if (mIsMessage)
		logReceivedFromUserEvent(mEvent, ev); /*in the sender's log will appear the 202 accepted from Flexisip server*/
}

void ForkMessageContext::onAcceptanceTimer() {
	LOGD("ForkMessageContext[%p]::onAcceptanceTimer()", this);
	acceptMessage();
	mAcceptanceTimer.reset(nullptr);
}

bool isMessageARCSFileTransferMessage(shared_ptr<RequestSipEvent>& ev) {
	sip_t* sip = ev->getSip();

	if (sip->sip_content_type && sip->sip_content_type->c_type &&
	    strcasecmp(sip->sip_content_type->c_type, "application/vnd.gsma.rcs-ft-http+xml") == 0) {
		return true;
	}
	return false;
}

bool isConversionFromRcsToExternalBodyUrlNeeded(shared_ptr<ExtendedContact>& ec) {
	list<string> acceptHeaders = ec->mAcceptHeader;
	if (acceptHeaders.size() == 0) {
		return true;
	}

	for (auto it = acceptHeaders.begin(); it != acceptHeaders.end(); ++it) {
		string header = *it;
		if (header.compare("application/vnd.gsma.rcs-ft-http+xml") == 0) {
			return false;
		}
	}
	return true;
}

void ForkMessageContext::onNewBranch(const shared_ptr<BranchInfo>& br) {
	if (br->mUid.size() > 0) {
		/*check for a branch already existing with this uid, and eventually clean it*/
		shared_ptr<BranchInfo> tmp = findBranchByUid(br->mUid);
		if (tmp) {
			removeBranch(tmp);
		}
	} else {
		SLOGE << errorLogPrefix() << "No unique id found for contact";
	}
}

void ForkMessageContext::onNewRegister(const SipUri& dest,
                                       const std::string& uid,
                                       const std::shared_ptr<ExtendedContact>& newContact) {
	LOGD("ForkMessageContext[%p] onNewRegister", this);
	const auto& sharedListener = mListener.lock();
	if (!sharedListener) {
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
			LOGD("ForkMessageContext::onNewRegister(): this is a new client instance.");
			sharedListener->onDispatchNeeded(shared_from_this(), newContact);
			return;
		} else if (br->needsDelivery()) {
			// this is a client for which the message wasn't delivered yet (or failed to be delivered). The message
			// needs to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this client is reconnecting but was not delivered before.");
			sharedListener->onDispatchNeeded(shared_from_this(), newContact);
			return;
		}
	}
	// in all other case we can accept a new transaction only if the message hasn't been delivered already.
	LOGD("Message has been delivered %i times.", mDeliveredCount);

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
	dbObject.isMessage = mIsMessage;
	dbObject.isFinished = mFinished;
	dbObject.msgPriority = mMsgPriority;
	dbObject.deliveredCount = mDeliveredCount;
	dbObject.currentPriority = mCurrentPriority;
	dbObject.expirationDate = *gmtime(&mExpirationDate);
	dbObject.request = mEvent->getMsgSip()->printString();
	dbObject.dbKeys.insert(dbObject.dbKeys.end(), mKeys.begin(), mKeys.end());
	for (const auto& waitingBranch : mWaitingBranches) {
		dbObject.dbBranches.push_back(waitingBranch->getDbObject());
	}

	return dbObject;
}

void ForkMessageContext::restoreBranch(const BranchInfoDb& dbBranch) {
	mWaitingBranches.push_back(BranchInfo::make(shared_from_this(), dbBranch, mAgent));
}

#ifdef ENABLE_UNIT_TESTS
void ForkMessageContext::assertEqual(const shared_ptr<ForkMessageContext>& expected) {
	BC_ASSERT_EQUAL(mIsMessage, expected->mIsMessage, bool, "%d");
	BC_ASSERT_EQUAL(mFinished, expected->mFinished, bool, "%d");
	BC_ASSERT_EQUAL((int)mMsgPriority, (int)expected->mMsgPriority, int, "%i");
	BC_ASSERT_EQUAL(mDeliveredCount, expected->mDeliveredCount, int, "%d");
	BC_ASSERT_EQUAL(mCurrentPriority, expected->mCurrentPriority, float, "%f");
	BC_ASSERT_EQUAL(mExpirationDate, expected->mExpirationDate, time_t, "%ld");
	BC_ASSERT_TRUE(mEvent->getMsgSip()->printString() == expected->mEvent->getMsgSip()->printString());

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
		equal(mWaitingBranches.begin(), mWaitingBranches.end(), expected->mWaitingBranches.begin(),
		      [](const auto& a, const auto& b) {
			      a->assertEqual(b);
			      return true;
		      });
	} else {
		BC_FAIL("Waiting branch list is not the same size");
	}
}
#endif
