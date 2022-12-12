/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/event.hh"
#include "flexisip/fork-context/branch-info.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/module-router.hh"
#include "flexisip/transaction.hh"

namespace flexisip {

class OnContactRegisteredListener;

class ForkContextBase : public ForkContext, public std::enable_shared_from_this<ForkContextBase> {
public:
	virtual ~ForkContextBase();

	using ShouldDispatchType = std::pair<DispatchStatus, std::shared_ptr<BranchInfo>>;

	/**
	 * Called by the Router module to create a new branch.
	 */
	std::shared_ptr<BranchInfo> addBranch(const std::shared_ptr<RequestSipEvent>& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) override;
	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const override;
	bool allBranchesAnswered(bool ignore_errors_and_timeouts = false) const;
	/**
	 * Request if the fork has other branches with lower priorities to try
	 */
	bool hasNextBranches() const override;
	/**
	 * Called when a fatal internal error is thrown in Flexisip. Send a custom response and cancel all branches if
	 * necessary.
	 * @param status The status of the custom response to send.
	 * @param phrase The content of the custom response to send.
	 */
	void processInternalError(int status, const char* phrase) override;
	// Start the processing of the highest priority branches that are not completed yet
	void start() override;

	void addKey(const std::string& key) override;
	const std::vector<std::string>& getKeys() const override;

	/**
	 * Notifies the cancellation of the fork process.
	 */
	void onCancel(const std::shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& ev) override;
	/**
	 * See PushNotificationContextObserver::onPushSent().
	 */
	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept override;
	const std::shared_ptr<RequestSipEvent>& getEvent() override;
	const std::shared_ptr<ForkContextConfig>& getConfig() const override {
		return mCfg;
	}
	bool isFinished() const override {
		return mFinished;
	};
	void checkFinished() override;
	sofiasip::MsgSipPriority getMsgPriority() const override {
		return mMsgPriority;
	};

	static const int sUrgentCodes[];
	static const int sAllCodesUrgent[];

protected:
	ForkContextBase(const std::shared_ptr<ModuleRouter>& router,
	                const std::shared_ptr<RequestSipEvent>& event,
	                const std::shared_ptr<ForkContextConfig>& cfg,
	                const std::weak_ptr<ForkContextListener>& listener,
	                const std::weak_ptr<StatPair>& counter,
	                sofiasip::MsgSipPriority priority,
	                bool isRestored = false);

	// Mark the fork process as terminated. The real destruction is performed asynchronously, in next main loop
	// iteration.
	void setFinished();
	// Used by derived class to allocate a derived type of BranchInfo if necessary.
	virtual std::shared_ptr<BranchInfo> createBranchInfo();
	// Notifies derived class of the creation of a new branch
	virtual void onNewBranch(const std::shared_ptr<BranchInfo>& br);
	// Notifies the expiry of the final fork timeout.
	virtual void onLateTimeout(){};
	// Requests the derived class if the fork context should finish now.
	virtual bool shouldFinish();
	// Notifies the destruction of the fork context. Implementers should use it to perform their initialization, but
	// shall never forget to upcall to the parent class !*/
	void onFinished();
	// Request the forwarding the last response from a given branch
	std::shared_ptr<ResponseSipEvent> forwardResponse(const std::shared_ptr<BranchInfo>& br);
	// Request the forwarding of a response supplied in argument.
	std::shared_ptr<ResponseSipEvent> forwardResponse(const std::shared_ptr<ResponseSipEvent>& br);
	/**
	 * Request the forwarding of a custom response created from parameters.
	 * @param status The status of the custom response to send.
	 * @param phrase The content of the custom response to send.
	 * @return A shared_ptr containing the ResponseSipEvent sent, can be empty.
	 */
	std::shared_ptr<ResponseSipEvent> forwardCustomResponse(int status, const char* phrase);

	// Get a branch by specifying its unique id
	std::shared_ptr<BranchInfo> findBranchByUid(const std::string& uid);
	// Get a branch by specifying its request URI destination.
	std::shared_ptr<BranchInfo> findBranchByDest(const SipUri& dest);
	// Get the best candidate among all branches for forwarding its responses.
	std::shared_ptr<BranchInfo> findBestBranch(const int urgentReplies[], bool avoid503And408 = false);
	int getLastResponseCode() const;
	void removeBranch(const std::shared_ptr<BranchInfo>& br);
	const std::list<std::shared_ptr<BranchInfo>>& getBranches() const;
	static bool isUrgent(int code, const int urgentCodes[]);
	void processLateTimeout();

	/**
	 * This implementation looks for already pending or failed transactions.
	 *
	 * @return Return a pair with :
	 *  - DispatchStatus : tell if you should dispatch a new branch/transaction to the device targeted by dest/uid.
	 *  - std::shared_ptr<BranchInfo> : the failed/unfinished branch/transaction you will replace if it exist or
	 * nullptr.
	 */
	ShouldDispatchType shouldDispatch(const SipUri& dest, const std::string& uid);
	/**
	 * Send a response in the incoming transaction associated to this ForkContext.
	 * @param status SIP response status.
	 * @param phrase SIP response phrase.
	 * @param addToTag If true, add a generated 'tag' parameter to the To-URI.
	 */
	void sendResponse(int status, char const* phrase, bool addToTag = false);

	const ForkContext* getPtrForEquality() const override {
		return this;
	}

	// Protected attributes
	bool m110Sent = false; /**< Whether a "110 Push sent" response has already been sent in the incoming transaction. */
	bool mFinished = false;
	float mCurrentPriority;
	Agent* mAgent;
	std::weak_ptr<ModuleRouter> mRouter;
	std::shared_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<ResponseSipEvent> mLastResponseSent;
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
	std::shared_ptr<BranchInfo> _findBestBranch(const int urgentReplies[], bool ignore503And408);
	// Set the next branches to try and process them
	void nextBranches();
	void onNextBranches();

	std::list<std::shared_ptr<BranchInfo>> mCurrentBranches;
	std::weak_ptr<StatPair> mStatCounter;
};

} // namespace flexisip
