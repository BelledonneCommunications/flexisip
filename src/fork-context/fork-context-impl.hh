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

#pragma once

#include <memory>

#include "agent-interface.hh"
#include "branch-info.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "fork-context.hh"
#include "fork-strategy/fork-strategy.hh"
#include "router/injector.hh"
#include "transaction/incoming-transaction.hh"

namespace flexisip {

class OnContactRegisteredListener;

/**
 * @brief Base class for all ForkContext implementations. It provides the basic functionality to manage the fork process
 * and the branches.
 */
class ForkContextImpl : public ForkContext, public std::enable_shared_from_this<ForkContextImpl> {
public:
	template <typename... Args>
	static std::shared_ptr<ForkContextImpl> make(Args&&... args) {
		return std::shared_ptr<ForkContextImpl>(new ForkContextImpl{std::forward<Args>(args)...});
	}
	static bool isUrgent(int code, const int urgentCodes[]);

	~ForkContextImpl() override;

	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept final;

	std::shared_ptr<BranchInfo> addBranch(std::unique_ptr<RequestSipEvent>&& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) final;
	bool allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const final;
	bool hasNextBranches() const final;
	void processInternalError(int status, const char* phrase) final;
	void start() final;
	void addKey(const std::string& key) final;
	const std::vector<std::string>& getKeys() const final;
	void onCancel(const sofiasip::MsgSip& ms) final;
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) final;
	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;
	bool isFinished() const final;
	void tryToSendFinalResponse() final;
	RequestSipEvent& getEvent() final;
	sofiasip::MsgSipPriority getMsgPriority() const final;
	const std::shared_ptr<ForkContextConfig>& getConfig() const final;
	const std::shared_ptr<IncomingTransaction>& getIncomingTransaction() const final;

	/**
	 * @param finalStatusMode fork mode to consider for the final status answer of a branch
	 * @return 'true' if all waiting branches have been answered (see @FinalStatusMode for more information)
	 */
	bool allBranchesAnswered(FinalStatusMode finalStatusMode) const;

	std::unique_ptr<ResponseSipEvent> onSendResponse(std::unique_ptr<ResponseSipEvent>&& event) final;

	const ForkContext* getPtrForEquality() const final;
	const IForkStrategy& getStrategy() {
		return *mStrategy;
	}

protected:
	ForkContextImpl(AgentInterface* agent,
	                const std::shared_ptr<ForkContextConfig>& cfg,
	                const std::weak_ptr<InjectorListener>& injectorListener,
	                const std::weak_ptr<ForkContextListener>& forkContextListener,
	                std::unique_ptr<RequestSipEvent>&& event,
	                sofiasip::MsgSipPriority priority,
	                const std::weak_ptr<StatPair>& counter,
	                std::unique_ptr<IForkStrategy>&& forkStrategy,
	                bool isRestored = false);

	/**
	 * @brief Find the best branch to take the response from and forward it to all the other branches.
	 */
	std::shared_ptr<BranchInfo> findBestBranch(bool ignore503And408 = false) const;
	void executeOnLateTimeout();

	bool mFinished{};
	float mCurrentPriority{-1.f};
	AgentInterface* mAgent;
	sofiasip::Timer mLateTimer;
	std::vector<std::string> mKeys;
	std::list<std::shared_ptr<BranchInfo>> mWaitingBranches;
	sofiasip::MsgSipPriority mMsgPriority = sofiasip::MsgSipPriority::Normal;

private:
	static bool isUseful4xx(int statusCode);

	/**
	 * @return 'true' if the fork process should be terminated.
	 */
	bool shouldFinish(bool ignoreForkLate = false);
	/**
	 * @brief Start the finish timer to schedule instance destruction.
	 *
	 * @note the real destruction is performed asynchronously, in the next main loop iteration.
	 */
	void setFinished();
	/**
	 * @breif Notify the destruction of the fork context.
	 *
	 * @warning implementers should use it to perform their initialization but shall never forget to call the parent
	 * class!
	 */
	void onFinished();
	/**
	 * @brief Build the list of next branches to try.
	 *
	 * @note the result is stored in the list of current branches.
	 */
	void nextBranches();
	/**
	 * @brief Start the next branches if there are any.
	 */
	void onNextBranches();
	/**
	 * @brief Remove a branch from the list of branches (both current and waiting branches lists).
	 *
	 * @param br branch to remove
	 */
	void removeBranch(const std::shared_ptr<BranchInfo>& br);
	struct ShouldDispatchType {
		// Tell if we should dispatch a new branch/transaction to the device targeted by dest/uid.
		DispatchStatus status;
		// The failed/unfinished branch/transaction you will replace if it exists.
		std::shared_ptr<BranchInfo> branch;
	};
	/**
	 * @brief Look for already pending or failed transactions.
	 */
	ShouldDispatchType shouldDispatch(const SipUri& dest, const std::string& uid);

	/**
	 * @brief Send a response in the incoming transaction associated with this ForkContext.
	 *
	 * @param status SIP response status code.
	 * @param phrase SIP response phrase.
	 * @param addToTag if 'true', add a generated 'tag' parameter to the 'To' header of the response
	 */
	void sendResponse(int status, char const* phrase, bool addToTag = false);
	/**
	 * @brief Send a custom response.
	 *
	 * @param status the status of the custom response to send
	 * @param phrase the content of the custom response to send
	 * @return the response sent, or nullptr if the response was not sent
	 */
	std::unique_ptr<ResponseSipEvent> sendCustomResponse(int status, const char* phrase);

	void applyResponseStrategy(ResponseStrategy respStrategy);
	std::shared_ptr<BranchInfo> findBranchByUid(const std::string& uid);
	std::shared_ptr<BranchInfo> findBranchByDest(const SipUri& dest);

	/**
	 * @return 'true' if one of the branches received a response in the [180;200[ range
	 */
	bool isRingingSomewhere() const;
	/**
	 * @return last response code or 0 if no response was sent
	 */
	int getLastResponseCode() const;

	// Whether a "110 Push sent" response has already been sent in the incoming transaction or not.
	bool m110Sent{};
	std::shared_ptr<MsgSip> mLastResponseSent;
	std::weak_ptr<ForkContextListener> mForkContextListener;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::shared_ptr<ForkContextConfig> mCfg;
	// Timeout after which an answer must be sent through the incoming transaction even if no success response was
	// received on the outgoing transactions.
	sofiasip::Timer mDecisionTimer;
	sofiasip::Timer mFinishTimer;
	sofiasip::Timer mNextBranchesTimer;
	std::weak_ptr<InjectorListener> mInjectorListener;
	std::unique_ptr<RequestSipEvent> mEvent;
	std::list<std::shared_ptr<BranchInfo>> mCurrentBranches;
	std::weak_ptr<StatPair> mStatCounter;
	std::string mLogPrefix;
	std::unique_ptr<IForkStrategy> mStrategy;
};

} // namespace flexisip