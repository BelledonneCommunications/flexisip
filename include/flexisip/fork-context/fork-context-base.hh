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

#include "flexisip/agent.hh"
#include "flexisip/event.hh"
#include "flexisip/fork-context/branch-info.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/registrardb.hh"
#include "flexisip/transaction.hh"

namespace flexisip {

class OnContactRegisteredListener;

class ForkContextBase : public ForkContext, public std::enable_shared_from_this<ForkContextBase>  {
private:
	void init();
	void processLateTimeout();
	std::shared_ptr<BranchInfo> _findBestBranch(const int urgentReplies[], bool ignore503And408);
	std::shared_ptr<OnContactRegisteredListener> mContactRegisteredListener;
	// Set the next branches to try and process them
	void nextBranches();
	void onNextBranches();

	std::weak_ptr<ForkContextListener> mListener;
	sofiasip::Timer mNextBranchesTimer;
	std::list<std::shared_ptr<BranchInfo>> mWaitingBranches;
	std::list<std::shared_ptr<BranchInfo>> mCurrentBranches;
	std::weak_ptr<StatPair> mStatCounter;
	float mCurrentPriority;
	bool mFinished = false;
	std::list<std::string> mKeys;

protected:
	ForkContextBase(Agent* agent, const std::shared_ptr<RequestSipEvent>& event,
	                const std::shared_ptr<ForkContextConfig>& cfg, const std::weak_ptr<ForkContextListener>& listener,
	                const std::weak_ptr<StatPair>& counter);

	// Mark the fork process as terminated. The real destruction is performed asynchronously, in next main loop
	// iteration.
	void setFinished();
	// Used by derived class to allocate a derived type of BranchInfo if necessary.
	virtual std::shared_ptr<BranchInfo> createBranchInfo();
	// Notifies derived class of the creation of a new branch
	virtual void onNewBranch(const std::shared_ptr<BranchInfo> &br);
	// Notifies the expiry of the final fork timeout.
	virtual void onLateTimeout() {};
	// Requests the derived class if the fork context should finish now.
	virtual bool shouldFinish();
	// Notifies the destruction of the fork context. Implementors should use it to perform their unitialization, but
	// shall never forget to upcall to the parent class !*/
	virtual void onFinished();
	// Request the forwarding the last response from a given branch
	std::shared_ptr<ResponseSipEvent> forwardResponse(const std::shared_ptr<BranchInfo> &br);
	// Request the forwarding of a response supplied in argument.
	std::shared_ptr<ResponseSipEvent> forwardResponse(const std::shared_ptr<ResponseSipEvent> &br);
	/**
	 * Request the forwarding of a custom response created from parameters.
	 * @param status The status of the custom response to send.
	 * @param phrase The content of the custom response to send.
	 * @return A shared_ptr containing the ResponseSipEvent sent, can be empty.
	 */
	std::shared_ptr<ResponseSipEvent> forwardCustomResponse(int status, const char* phrase);

	// Get a branch by specifying its unique id
	std::shared_ptr<BranchInfo> findBranchByUid(const std::string &uid);
	// Get a branch by specifying its request uri destination.
	std::shared_ptr<BranchInfo> findBranchByDest(const url_t *dest);
	// Get the best candidate among all branches for forwarding its responses.
	std::shared_ptr<BranchInfo> findBestBranch(const int urgentReplies[], bool avoid503And408 = false);
	bool allBranchesAnswered(bool ignore_errors_and_timeouts = false) const;
	int getLastResponseCode() const;
	void removeBranch(const std::shared_ptr<BranchInfo> &br);
	const std::list<std::shared_ptr<BranchInfo>> &getBranches() const;
	static bool isUrgent(int code, const int urgentCodes[]);

	Agent* mAgent;
	std::shared_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<ResponseSipEvent> mLastResponseSent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::shared_ptr<ForkContextConfig> mCfg;
	sofiasip::Timer mLateTimer;
	sofiasip::Timer mFinishTimer;

public:
	virtual ~ForkContextBase();

	// Called by the Router module to create a new branch.
	void addBranch(const std::shared_ptr<RequestSipEvent>& ev,
	               const std::shared_ptr<ExtendedContact>& contact) override;
	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const override;
	// Request if the fork has other branches with lower priorities to try
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
	const std::list<std::string>& getKeys() const override;

	/*
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination, then it should return true, false otherwise.
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	 **/
	bool onNewRegister(const url_t* dest, const std::string& uid) override;
	void onPushSent(const std::shared_ptr<OutgoingTransaction>& tr) override;
	void onPushError(const std::shared_ptr<OutgoingTransaction>& tr, const std::string& errormsg) override;
	// Notifies the cancellation of the fork process.
	void onCancel(const std::shared_ptr<RequestSipEvent> &ev) override;
	const std::shared_ptr<RequestSipEvent>& getEvent() override;
	const std::shared_ptr<ForkContextConfig>& getConfig() const override {
		return mCfg;
	}
	bool isFinished() const override {
		return mFinished;
	};

	static const int sUrgentCodes[];
	static const int sAllCodesUrgent[];
};

}
