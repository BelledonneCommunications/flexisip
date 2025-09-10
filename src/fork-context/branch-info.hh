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
#include "fork-context.hh"
#include "fork-status.hh"
#include "modules/module-pushnotification.hh"
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
 * UID. Then, the listener is automatically moved to the new branch. So, when you attach a listener to a branch, keep in
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

struct CancelInfo {
	CancelInfo(sip_reason_t* reason);
	CancelInfo(sofiasip::Home& home, const ForkStatus& status);

	ForkStatus mStatus;
	sip_reason_t* mReason{};
};

/**
 * @brief Branch of a fork context.
 */
class BranchInfo : public std::enable_shared_from_this<BranchInfo> {
public:
	template <typename... Args>
	static std::shared_ptr<BranchInfo> make(Args&&... args) {
		const auto branch = std::shared_ptr<BranchInfo>{new BranchInfo{std::forward<Args>(args)...}};
		setBranchInfo(branch->mTransaction, std::weak_ptr{branch});
		return branch;
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
	 * @brief Process the response received on this branch and notifies the ForkContext consequently.
	 *
	 * @param event received response to process
	 */
	void processResponse(ResponseSipEvent& event);
	/**
	 * @brief Forward the last response received on the branch to the ForkContext.
	 *
	 * @return 'true' if a response was sent
	 */
	bool forwardResponse(bool forkContextHasIncomingTransaction);
	/**
	 * @brief Cancel the branch (send a '487 Request terminated' to the target).
	 *
	 * @warning Does not send the request if the branch has already sent or received a terminal response. Same behavior
	 * if it did not receive a response yet and that keepAppleVoIpAlive is set to 'true' (for iOS devices only,
	 * Invite/Cancel feature).
	 * @param information cancellation reason
	 * @param keepAppleVoIpAlive prevent cancellation for the Invite/Cancel feature
	 */
	void cancel(const std::optional<CancelInfo>& information, bool keepAppleVoIpAlive = false);
	/**
	 * @return status of the last response
	 */
	virtual int getStatus() const;
	/**
	 * @return 'true' if the SIP message (response) needs to be sent to the target of this branch.
	 */
	bool needsDelivery(FinalStatusMode mode = FinalStatusMode::RFC) const;
	/**
	 * @return 'true' if the push context of this branch is Apple::VoIP.
	 */
	bool pushContextIsAppleVoIp() const;

	std::string getUid() const;
	std::optional<SipUri> getRequestUri() const;
	float getPriority() const;
	int getClearedCount() const;
	std::weak_ptr<BranchInfoListener> getListener() const;
	std::shared_ptr<const ExtendedContact> getContact() const;
	std::shared_ptr<ForkContext> getForkContext() const;
	const std::unique_ptr<ResponseSipEvent>& getLastResponseEvent() const;
	std::shared_ptr<PushNotificationContext> getPushNotificationContext() const;
	std::shared_ptr<MsgSip> getRequestMsg() const;
	BranchInfoDb getDbObject() const;

	std::unique_ptr<RequestSipEvent>&& extractRequest();

	void setListener(const std::weak_ptr<BranchInfoListener>& listener);
	void setForkContext(const std::shared_ptr<ForkContext>& forkContext);
	void setPushNotificationContext(const std::shared_ptr<PushNotificationContext>& context);

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<BranchInfo>& expected) {
		BC_ASSERT_STRING_EQUAL(mUid.c_str(), expected->mUid.c_str());
		BC_ASSERT_EQUAL(mPriority, expected->mPriority, float, "%f");

		BC_ASSERT_TRUE(mRequestMsg->msgAsString() == expected->mRequestMsg->msgAsString());
		BC_ASSERT_TRUE(mLastResponse->msgAsString() == expected->mLastResponse->msgAsString());
	}
#endif

protected:
	/**
	 * @brief Used to create an empty fake branch.
	 */
	BranchInfo() = default;

	template <typename T>
	BranchInfo(T&& ctx) : mForkCtx{std::forward<T>(ctx)} {};

	BranchInfo(std::unique_ptr<RequestSipEvent>&& ev,
	           const std::shared_ptr<ForkContext>& context,
	           const std::shared_ptr<ExtendedContact>& contact,
	           const std::weak_ptr<BranchInfoListener>& listener,
	           const std::weak_ptr<PushNotificationContext>& pushContext,
	           int clearedCount);

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
		mLastResponseEvent->setIncomingAgent(nullptr);
		mLastResponse = mLastResponseEvent->getMsgSip();
		mLogPrefix = LogManager::makeLogPrefixForInstance(this, "BranchInfo");
	}

private:
	std::unique_ptr<RequestSipEvent> mRequestEvent{};
	std::weak_ptr<ForkContext> mForkCtx{};
	std::shared_ptr<ExtendedContact> mContact{};
	std::shared_ptr<MsgSip> mRequestMsg{};
	std::shared_ptr<OutgoingTransaction> mTransaction{};
	std::string mUid{};
	float mPriority{1.f};
	std::weak_ptr<BranchInfoListener> mListener{};
	std::unique_ptr<ResponseSipEvent> mLastResponseEvent{};
	std::shared_ptr<MsgSip> mLastResponse{};
	// Count every time a branch with the same Uid is cleared for a given fork context. Can be used to know if a push
	// notification has already been sent for this branch.
	int mClearedCount{};
	// Only used with Invite/ForkCall.
	std::weak_ptr<PushNotificationContext> mPushContext{};
	bool mWaitingAppleClientResponse{};
	std::string mLogPrefix{};
};

} // namespace flexisip