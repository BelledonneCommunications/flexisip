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

#include "agent-interface.hh"
#include "branch-info-db.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "fork-status.hh"
#include "module-pushnotification.hh"
#include "transaction/outgoing-transaction.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

namespace flexisip {

class ForkContext;
struct ExtendedContact;

enum class FinalStatusMode {
	// Every status >= 200 is considered as a final status.
	RFC,
	// Every status >= 200 is considered as a final status EXCEPT 408 and 503.
	ForkLate,
};

/**
 * @brief Allow to be notified when a branch is canceled by the ForkContext or when a branch is completed (i.e.,
 * received its final response).
 *
 * @warning If 'fork-late' mode is enabled, a branch may be removed to be replaced by a new one with the same device
 * UID. Then, the listener is automatically moved in the new branch. So, when you attach a listener to a branch, keep in
 * mind that you subscribe to the event of a given UID instead of a specific branch.
 */
class BranchInfoListener {
public:
	virtual ~BranchInfoListener() noexcept = default;

	/**
	 * @brief Notify cancellation by the ForkContext.
	 *
	 * @param branch the branch which has been canceled
	 * @param reason information about the scenario which caused the cancellation
	 */
	virtual void onBranchCanceled(const std::shared_ptr<BranchInfo>&, ForkStatus) noexcept {};
	/**
	 * @brief Notify receipt of a final response by the ForkContext (see @FinalStatusMode for more information).
	 */
	virtual void onBranchCompleted(const std::shared_ptr<BranchInfo>&) noexcept {};
};

/**
 * @brief Branch of a fork context.
 */
class BranchInfo : public std::enable_shared_from_this<BranchInfo> {
public:
	template <typename... Args>
	static std::shared_ptr<BranchInfo> make(Args&&... args) {
		return std::shared_ptr<BranchInfo>{new BranchInfo{std::forward<Args>(args)...}};
	}

	virtual ~BranchInfo() = default;

	/**
	 * @return the BranchInfo instance corresponding to the provided transaction or nullptr if none were found.
	 */
	static std::shared_ptr<BranchInfo> getBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr);
	/**
	 * @brief Associate a BranchInfo instance with the provided outgoing transaction.
	 */
	static void setBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr, const std::weak_ptr<BranchInfo>& br);
	/**
	 * @brief Notify the listener that this branch has been canceled.
	 *
	 * @param cancelReason reason of cancellation
	 */
	void notifyBranchCanceled(ForkStatus cancelReason) noexcept;
	/**
	 * @brief Notify the listener that this branch is now completed.
	 */
	void notifyBranchCompleted() noexcept;
	/**
	 * @return status of the last response
	 */
	virtual int getStatus();
	/**
	 * @return 'true' if the SIP message needs to be sent to the targe of this branch.
	 */
	bool needsDelivery(FinalStatusMode mode = FinalStatusMode::RFC);

	BranchInfoDb getDbObject();

	std::unique_ptr<RequestSipEvent>&& extractRequest();
	void setRequest(std::unique_ptr<RequestSipEvent>&& req);

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
	// Count every time a branch with the same Uid is cleared for a given fork context. Can be used to know if a push
	// notification has already been sent for this branch.
	int mClearedCount{0};
	// Only used with Invite/ForkCall.
	std::weak_ptr<PushNotificationContext> pushContext{};

protected:
	/**
	 * @brief Used to create an empty fake branch.
	 */
	BranchInfo() = default;

	template <typename T>
	BranchInfo(T&& ctx) : mForkCtx{std::forward<T>(ctx)} {
	}

	/**
	 * @brief Create an instance from information stored in the database when 'fork-late' mode is enabled.
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