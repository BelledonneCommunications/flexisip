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
#include "branch-info.hh"
#include "flexisip/event.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/module-router.hh"
#include "transaction/incoming-transaction.hh"

namespace flexisip {

class OnContactRegisteredListener;

/**
 * @brief Base class for all ForkContext implementations. It provides the basic functionality to manage the fork process
 * and the branches.
 */
class ForkContextBase : public ForkContext, public std::enable_shared_from_this<ForkContextBase> {
public:
	static constexpr int kUrgentCodes[] = {401, 407, 415, 420, 484, 488, 606, 603, 0};
	static constexpr int kAllCodesUrgent[] = {-1, 0};

	~ForkContextBase() override;

	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept override;

	std::shared_ptr<BranchInfo> addBranch(std::unique_ptr<RequestSipEvent>&& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) override;
	bool allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const override;
	bool hasNextBranches() const override;
	void processInternalError(int status, const char* phrase) override;
	void start() override;
	void addKey(const std::string& key) override;
	const std::vector<std::string>& getKeys() const override;
	void onCancel(const sofiasip::MsgSip& ms) override;
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) override;
	bool isFinished() const override;
	std::shared_ptr<BranchInfo> checkFinished() override;
	RequestSipEvent& getEvent() override;
	sofiasip::MsgSipPriority getMsgPriority() const override;
	const std::shared_ptr<ForkContextConfig>& getConfig() const override;

	/**
	 * @param finalStatusMode fork mode to consider for the final status answer of a branch
	 * @return 'true' if all waiting branches have been answered (see @FinalStatusMode for more information)
	 */
	bool allBranchesAnswered(FinalStatusMode finalStatusMode) const;

protected:
	struct ShouldDispatchType {
		// Tell if we should dispatch a new branch/transaction to the device targeted by dest/uid.
		DispatchStatus status;
		// The failed/unfinished branch/transaction you will replace if it exists.
		std::shared_ptr<BranchInfo> branch;
	};

	ForkContextBase(const std::shared_ptr<ModuleRouterInterface>& router,
	                AgentInterface* agent,
	                const std::shared_ptr<ForkContextConfig>& cfg,
	                const std::weak_ptr<ForkContextListener>& listener,
	                std::unique_ptr<RequestSipEvent>&& event,
	                const std::weak_ptr<StatPair>& counter,
	                sofiasip::MsgSipPriority priority,
	                bool isRestored = false);

	static bool isUseful4xx(int statusCode);
	static bool isUrgent(int code, const int urgentCodes[]);

	const ForkContext* getPtrForEquality() const override;

	/**
	 * @return new branch for this ForkContext
	 */
	virtual std::shared_ptr<BranchInfo> createBranchInfo();
	/**
	 * @brief Notify the creation of a new branch for this ForkContext.
	 */
	virtual void onNewBranch(const std::shared_ptr<BranchInfo>&) {};
	/**
	 * @brief Notify the expiry of the final fork timeout.
	 */
	virtual void onLateTimeout() {};
	/**
	 * @return 'true' if the fork process should be terminated.
	 */
	virtual bool shouldFinish();

	/**
	 * @brief Mark the fork process as terminated.
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
	 * @brief Forward the last response received on the branch.
	 *
	 * @param br the branch containing the response to send
	 * @return 'true' if a response was sent
	 */
	bool forwardResponse(const std::shared_ptr<BranchInfo>& br);
	/**
	 * @brief Forward a response.
	 *
	 * @param ev response to be forwarded
	 * @return the response sent, or nullptr if the response was not sent
	 */
	std::unique_ptr<ResponseSipEvent> forwardResponse(std::unique_ptr<ResponseSipEvent>&& ev);
	/**
	 * @brief Forward a custom response.
	 *
	 * @param status the status of the custom response to send
	 * @param phrase the content of the custom response to send
	 * @return the response sent, or nullptr if the response was not sent
	 */
	std::unique_ptr<ResponseSipEvent> forwardCustomResponse(int status, const char* phrase);
	/**
	 * @brief Remove a branch from the list of branches (both current and waiting branches lists).
	 *
	 * @param br branch to remove
	 */
	void removeBranch(const std::shared_ptr<BranchInfo>& br);
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
	void processLateTimeout();

	/**
	 * @brief Find the best branch to take the response from and forward it to all the other branches.
	 */
	std::shared_ptr<BranchInfo> findBestBranch(bool ignore503And408 = false);
	std::shared_ptr<BranchInfo> findBranchByUid(const std::string& uid);
	std::shared_ptr<BranchInfo> findBranchByDest(const SipUri& dest);
	/**
	 * @return the list of waiting branches
	 */
	const std::list<std::shared_ptr<BranchInfo>>& getBranches() const;
	/**
	 * @return last response code or 0 if no response was sent
	 */
	int getLastResponseCode() const;

	// Whether a "110 Push sent" response has already been sent in the incoming transaction or not.
	bool m110Sent;
	bool mFinished;
	float mCurrentPriority;
	AgentInterface* mAgent;
	std::weak_ptr<ModuleRouterInterface> mRouter;
	std::shared_ptr<MsgSip> mLastResponseSent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::shared_ptr<ForkContextConfig> mCfg;
	sofiasip::Timer mLateTimer;
	sofiasip::Timer mFinishTimer;
	std::vector<std::string> mKeys;
	std::list<std::shared_ptr<BranchInfo>> mWaitingBranches;
	sofiasip::Timer mNextBranchesTimer;
	sofiasip::MsgSipPriority mMsgPriority = sofiasip::MsgSipPriority::Normal;
	std::weak_ptr<ForkContextListener> mListener;

private:
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

	std::unique_ptr<RequestSipEvent> mEvent;
	std::list<std::shared_ptr<BranchInfo>> mCurrentBranches;
	std::weak_ptr<StatPair> mStatCounter;
	std::string mLogPrefix;
};

} // namespace flexisip