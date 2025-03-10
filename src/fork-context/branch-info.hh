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

#pragma once

#include <memory>

#include "flexisip/fork-context/fork-context.hh"

#include "agent-interface.hh"
#include "branch-info-db.hh"
#include "fork-status.hh"
#include "module-pushnotification.hh"
#include "transaction/outgoing-transaction.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

namespace flexisip {

class ForkContext;
struct ExtendedContact;

/**
 * Interface for BranchInfo listener.
 *
 * BranchInfo listeners allow to be notified when a branch is canceled by
 * the ForkContext and when a branch is completed (i.e. received its final response).
 *
 * @warning Should fork-late mode be enabled, a branch may be removed to be replaced
 * by a new one with the same device UID. Then, the listener is automatically moved
 * in the new branch. So, when you attach a listener to a branch, keep in mind that
 * you subscribe to the event of a given UID instead of a specific branch.
 */
class BranchInfoListener {
public:
	virtual ~BranchInfoListener() noexcept = default;

	/**
	 * Called when the branch is canceled by the ForkContext.
	 * @param[in] br The branch which has been canceled.
	 * @param[in] cancelReason Give information about the scenario which caused the cancellation.
	 */
	virtual void onBranchCanceled([[maybe_unused]] const std::shared_ptr<BranchInfo>& br,
	                              [[maybe_unused]] ForkStatus cancelReason) noexcept {
	}
	/**
	 * Called when a branch receives a final response (statusCode >= 200).
	 */
	virtual void onBranchCompleted([[maybe_unused]] const std::shared_ptr<BranchInfo>& br) noexcept {
	}
};

enum class FinalStatusMode {
	RFC, /*Every status >= 200 is considered as a final status*/
	ForkLate /*Every status >= 200 is considered as a final status EXCEPT 408 and 503*/,
};

class BranchInfo : public std::enable_shared_from_this<BranchInfo> {
public:
	virtual ~BranchInfo() = default;

	// Call the matching private ctor and instantiate as a shared_ptr.
	template <typename... Args>
	static std::shared_ptr<BranchInfo> make(Args&&... args) {
		return std::shared_ptr<BranchInfo>{new BranchInfo{std::forward<Args>(args)...}};
	}

	void notifyBranchCanceled(ForkStatus cancelReason) noexcept {
		if (auto listener = mListener.lock()) listener->onBranchCanceled(shared_from_this(), cancelReason);
	}
	void notifyBranchCompleted() noexcept {
		if (auto listener = mListener.lock()) listener->onBranchCompleted(shared_from_this());
	}

	virtual int getStatus() {
		return mLastResponse ? mLastResponse->getSip()->sip_status->st_status : 0;
	}

	// Obtain the BranchInfo corresponding to an outgoing transaction
	static std::shared_ptr<BranchInfo> getBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr) {
		return tr ? tr->getProperty<BranchInfo>("BranchInfo") : nullptr;
	}

	// Set the BranchInfo managed by an outoing transaction
	static void setBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr, const std::weak_ptr<BranchInfo> br) {
		if (tr) tr->setProperty("BranchInfo", br);
	}

	bool needsDelivery(FinalStatusMode mode = FinalStatusMode::RFC) {
		auto currentStatus = getStatus();

		switch (mode) {
			case FinalStatusMode::ForkLate:
				return currentStatus < 200 || currentStatus == 503 || currentStatus == 408;
			case FinalStatusMode::RFC:
			default:
				return currentStatus < 200;
		}
	}

	BranchInfoDb getDbObject() {
		std::string request{mRequestMsg->msgAsString()};
		std::string lastResponse{mLastResponse->msgAsString()};
		BranchInfoDb branchInfoDb{mUid, mPriority, request, lastResponse, mClearedCount};
		return branchInfoDb;
	}

	std::unique_ptr<RequestSipEvent>&& extractRequest() {
		return std::move(mRequestEvent);
	}
	void setRequest(std::unique_ptr<RequestSipEvent>&& req) {
		mRequestEvent = std::move(req);
	}

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<BranchInfo>& expected) {
		BC_ASSERT_STRING_EQUAL(mUid.c_str(), expected->mUid.c_str());
		BC_ASSERT_EQUAL(mPriority, expected->mPriority, float, "%f");

		BC_ASSERT_TRUE(mRequestMsg->msgAsString() == expected->mRequestMsg->msgAsString());
		BC_ASSERT_TRUE(mLastResponse->msgAsString() == expected->mLastResponse->msgAsString());
	}
#endif

	std::weak_ptr<ForkContext> mForkCtx{};
	std::weak_ptr<BranchInfoListener> mListener{};
	std::string mUid{};
	std::shared_ptr<MsgSip> mRequestMsg{};
	std::shared_ptr<OutgoingTransaction> mTransaction{};
	std::unique_ptr<ResponseSipEvent> mLastResponseEvent{};
	std::shared_ptr<MsgSip> mLastResponse{};
	std::shared_ptr<ExtendedContact> mContact{};
	float mPriority{1.0f};

	/*
	 * Count every time a branch with the same Uid is cleared for a given fork context.
	 * Can be used to know if a push notification has already been sent for this branch.
	 */
	int mClearedCount{0};

	/**
	 * Only used with Invite/ForkCall
	 */
	std::weak_ptr<PushNotificationContext> pushContext{};

protected:
	/**
	 * Used to create an empty fake branch
	 */
	BranchInfo() = default;

	template <typename T>
	BranchInfo(T&& ctx) : mForkCtx{std::forward<T>(ctx)} {
	}

	/**
	 * Used when restoring BranchInfo from database in fork-late mode.
	 */
	template <typename T>
	BranchInfo(T&& ctx, const BranchInfoDb& dbObject, AgentInterface* agent) : mForkCtx{std::forward<T>(ctx)} {
		mUid = dbObject.contactUid;
		mClearedCount = dbObject.clearedCount;
		mPriority = dbObject.priority;
		mRequestMsg = std::make_shared<MsgSip>(0, dbObject.request);
		mRequestEvent = std::make_unique<RequestSipEvent>(agent->getIncomingAgent(), mRequestMsg);
		auto lastResponse =
		    !dbObject.lastResponse.empty() ? std::make_shared<MsgSip>(0, dbObject.lastResponse) : nullptr;
		mLastResponseEvent = std::make_unique<ResponseSipEvent>(agent->getOutgoingAgent(), lastResponse);
		mLastResponseEvent->setIncomingAgent(std::shared_ptr<IncomingAgent>());
		mLastResponse = mLastResponseEvent->getMsgSip();
	}

private:
	std::unique_ptr<RequestSipEvent> mRequestEvent{};
};

inline std::ostream& operator<<(std::ostream& os, const BranchInfo* br) noexcept {
	return (os << "BranchInfo[" << static_cast<const void*>(br) << "]");
}
inline std::ostream& operator<<(std::ostream& os, const std::shared_ptr<BranchInfo>& br) noexcept {
	return operator<<(os, br.get());
}

} // namespace flexisip