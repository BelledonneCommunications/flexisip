/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <memory>

#include "flexisip/fork-context/branch-info-db.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/registrardb.hh"
#include "flexisip/transaction.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

namespace flexisip {

class BranchInfo {
public:
	template <typename T> BranchInfo(T&& ctx) : mForkCtx{std::forward<T>(ctx)} {
	}

	/**
	 * Used when restoring BranchInfo from database in fork-late mode.
	 */
	template <typename T>
	BranchInfo(T&& ctx, const BranchInfoDb& dbObject, const std::shared_ptr<Agent>& agent)
	    : mForkCtx{std::forward<T>(ctx)} {
		mUid = dbObject.contactUid;
		mPushSent = dbObject.isPushSent;
		mPriority = dbObject.priority;
		auto request = std::make_shared<MsgSip>(
		    msg_make(sip_default_mclass(), 0, dbObject.request.c_str(), dbObject.request.size()));
		mRequest = std::make_shared<RequestSipEvent>(agent, request);
		auto lastResponse = std::make_shared<MsgSip>(
		    msg_make(sip_default_mclass(), 0, dbObject.lastResponse.c_str(), dbObject.lastResponse.size()));
		mLastResponse = std::make_shared<ResponseSipEvent>(agent, lastResponse);
		mLastResponse->setIncomingAgent(std::shared_ptr<IncomingAgent>());
	}

	void clear() {
		mTransaction.reset();
		mRequest.reset();
		mLastResponse.reset();
		mForkCtx.reset();
	}

	int getStatus() {
		return mLastResponse ? mLastResponse->getMsgSip()->getSip()->sip_status->st_status : 0;
	}

	// Obtain the BranchInfo corresponding to an outgoing transaction
	static std::shared_ptr<BranchInfo> getBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr) {
		return tr->getProperty<BranchInfo>("BranchInfo");
	}

	// Set the BranchInfo managed by an outoing transaction
	static void setBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr, const std::weak_ptr<BranchInfo> br) {
		tr->setProperty("BranchInfo", br);
	}

	BranchInfoDb getDbObject() {
		std::string request{mRequest->getMsgSip()->print()};
		std::string lastResponse{mLastResponse->getMsgSip()->print()};
		BranchInfoDb branchInfoDb{mUid, mPriority, request, lastResponse, mPushSent};
		return branchInfoDb;
	}

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<BranchInfo>& expected){
		BC_ASSERT_STRING_EQUAL(mUid.c_str(), expected->mUid.c_str());
		BC_ASSERT_EQUAL(mPriority, expected->mPriority, float, "%f");

		BC_ASSERT_STRING_EQUAL(mRequest->getMsgSip()->print(), expected->mRequest->getMsgSip()->print());
		BC_ASSERT_STRING_EQUAL(mLastResponse->getMsgSip()->print(), expected->mLastResponse->getMsgSip()->print());
	}
#endif

	std::weak_ptr<ForkContext> mForkCtx{};
	std::string mUid{};
	std::shared_ptr<RequestSipEvent> mRequest{};
	std::shared_ptr<OutgoingTransaction> mTransaction{};
	std::shared_ptr<ResponseSipEvent> mLastResponse{};
	std::shared_ptr<ExtendedContact> mContact{};
	float mPriority{1.0f};
	bool mPushSent{false}; // Whether  push notification has been sent for this branch.
};

} // namespace flexisip
