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

#include "fork-context/fork-message-context.hh"

#include <algorithm>
#include <chrono>
#include <optional>

#include "flexisip/event.hh"
#include "fork-context/fork-strategy/message-fork-strategy.hh"
#include "fork-context/message-kind.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

using namespace std;
using namespace std::chrono;
using namespace flexisip;

std::shared_ptr<ForkMessageContext>
ForkMessageContext::restore(ForkMessageContextDb& forkContextFromDb,
                            const std::weak_ptr<ForkContextListener>& forkContextListener,
                            const std::weak_ptr<InjectorListener>& injectorListener,
                            Agent* agent,
                            const std::shared_ptr<ForkContextConfig>& config,
                            const std::weak_ptr<StatPair>& counter) {
	auto restoredEvent =
	    RequestSipEvent::makeRestored(agent->getIncomingAgent(), make_shared<MsgSip>(0, forkContextFromDb.request),
	                                  agent->findModuleByRole("Router"));
	auto kind = MessageKind{*restoredEvent->getSip(), forkContextFromDb.msgPriority};
	auto forkMsg = make_unique<MessageForkStrategy>(kind, true, config);
	forkMsg->setDeliveredCount(forkContextFromDb.deliveredCount);
	forkMsg->setExpirationDate(timegm(&forkContextFromDb.expirationDate));
	auto timeLeftUntilExpiration = system_clock::from_time_t(forkMsg->getExpirationDate()) - system_clock::now();
	if (timeLeftUntilExpiration < 0s) timeLeftUntilExpiration = 0s;

	const auto context = make(agent, config, injectorListener, forkContextListener, std::move(restoredEvent),
	                          forkContextFromDb.msgPriority, counter, std::move(forkMsg), true);

	context->mFinished = forkContextFromDb.isFinished;
	context->mCurrentPriority = forkContextFromDb.currentPriority;

	context->mLateTimer.set(
	    [forkMessageContext = weak_ptr<ForkMessageContext>{context}]() {
		    if (const auto context = forkMessageContext.lock()) {
			    context->executeOnLateTimeout();
		    }
	    },
	    timeLeftUntilExpiration);

	for (const auto& dbKey : forkContextFromDb.dbKeys)
		context->addKey(dbKey);

	for (const auto& dbBranch : forkContextFromDb.dbBranches)
		context->restoreBranch(dbBranch);

	return context;
}

ForkMessageContextDb ForkMessageContext::getDbObject() {
	ForkMessageContextDb dbObject{};
	dbObject.isFinished = mFinished;
	dbObject.msgPriority = mMsgPriority;
	const auto& forkMsg = dynamic_cast<const MessageForkStrategy&>(getStrategy());
	dbObject.deliveredCount = forkMsg.getDeliveredCount();
	dbObject.currentPriority = mCurrentPriority;
	const auto expirationDate = forkMsg.getExpirationDate();
	dbObject.expirationDate = *gmtime(&expirationDate);
	dbObject.request = getEvent().getMsgSip()->msgAsString();
	dbObject.dbKeys.insert(dbObject.dbKeys.end(), mKeys.begin(), mKeys.end());

	for (const auto& waitingBranch : mWaitingBranches)
		dbObject.dbBranches.push_back(waitingBranch->getDbObject());

	return dbObject;
}

void ForkMessageContext::restoreBranch(const BranchInfoDb& dbBranch) {
	mWaitingBranches.push_back(BranchInfo::make(shared_from_this(), dbBranch, mAgent));
}

#ifdef ENABLE_UNIT_TESTS
void ForkMessageContext::assertEqual(const shared_ptr<ForkMessageContext>& expected) {
	BC_ASSERT_EQUAL(mFinished, expected->mFinished, bool, "%d");
	BC_ASSERT_EQUAL(int(mMsgPriority), int(expected->mMsgPriority), int, "%i");
	const auto& forkMsg = dynamic_cast<const MessageForkStrategy&>(getStrategy());
	const auto& expectedForkMsg = dynamic_cast<const MessageForkStrategy&>(expected->getStrategy());
	BC_ASSERT_EQUAL(forkMsg.getDeliveredCount(), expectedForkMsg.getDeliveredCount(), int, "%d");
	BC_ASSERT_EQUAL(mCurrentPriority, expected->mCurrentPriority, float, "%f");
	BC_ASSERT_EQUAL(forkMsg.getExpirationDate(), expectedForkMsg.getExpirationDate(), time_t, "%ld");
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