/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/agent.hh>
#include <flexisip/event.hh>
#include <flexisip/transaction.hh>
#include <flexisip/registrardb.hh>

namespace flexisip {

class OnContactRegisteredListener;

struct ForkContextConfig {
	int mDeliveryTimeout = 0;	 /* in seconds, used for "late" forking*/
	int mUrgentTimeout = 5;		  /*timeout for sending buffered urgent or retryable reponses (like 415).*/
	int mPushResponseTimeout = 0; /*timeout for receiving response to push */
	int mCurrentBranchesTimeout = 0; /*timeout for receiving response on current branches*/
	bool mForkLate = false;
	bool mTreatAllErrorsAsUrgent = false; /*treat all SIP response code as urgent replies in the fork mechanism.*/
	bool mForkNoGlobalDecline = false;
	bool mTreatDeclineAsUrgent = false; /*treat 603 declined as a urgent response, only useful is mForkNoGlobalDecline==true*/
	bool mPermitSelfGeneratedProvisionalResponse = true; /* Self explicit. Ex: 110 Push sent, 180 Ringing*/
};

class ForkContext;

class ForkContextListener {
  public:
	virtual ~ForkContextListener() = default;
	virtual void onForkContextFinished(std::shared_ptr<ForkContext> ctx) = 0;
};

class BranchInfo {
  public:
	template <typename T>
	BranchInfo(T &&ctx) : mForkCtx{std::forward<T>(ctx)} {}

	void clear();
	int getStatus() {return mLastResponse ? mLastResponse->getMsgSip()->getSip()->sip_status->st_status : 0;}

	std::weak_ptr<ForkContext> mForkCtx{};
	std::string mUid{};
	std::shared_ptr<RequestSipEvent> mRequest{};
	std::shared_ptr<OutgoingTransaction> mTransaction{};
	std::shared_ptr<ResponseSipEvent> mLastResponse{};
	std::shared_ptr<ExtendedContact> mContact{};
	float mPriority{1.0f};
	bool mPushSent{false}; // Whether  push notification has been sent for this branch.
};

class ForkContext : public std::enable_shared_from_this<ForkContext> {
  private:
	ForkContextListener *mListener;
	sofiasip::Timer mNextBranchesTimer;
	std::list<std::shared_ptr<BranchInfo>> mWaitingBranches;
	std::list<std::shared_ptr<BranchInfo>> mCurrentBranches;
	float mCurrentPriority;
	bool mFinished = false;
	std::list<std::string> mKeys;
	void init();
	void processLateTimeout();
	std::shared_ptr<BranchInfo> _findBestBranch(const int urgentReplies[], bool ignore503And408);
	std::shared_ptr<OnContactRegisteredListener> mContactRegisteredListener;
	// Request if the fork has other branches with lower priorities to try
	bool hasNextBranches();
	// Set the next branches to try and process them
	void nextBranches();
	void onNextBranches();

  protected:
	Agent *mAgent;
	std::shared_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<ResponseSipEvent> mLastResponseSent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::shared_ptr<ForkContextConfig> mCfg;
	sofiasip::Timer mLateTimer;
	sofiasip::Timer mFinishTimer;
	// Mark the fork process as terminated. The real destruction is performed asynchrously, in next main loop iteration.
	void setFinished();
	// Used by derived class to allocate a derived type of BranchInfo if necessary.
	virtual std::shared_ptr<BranchInfo> createBranchInfo();
	// Notifies derived class of the creation of a new branch
	virtual void onNewBranch(const std::shared_ptr<BranchInfo> &br);
	// Notifies the cancellation of the fork process.
	virtual void onCancel(const std::shared_ptr<RequestSipEvent> &ev);
	// Notifies the arrival of a new response on a given branch
	virtual void onResponse(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &event) = 0;
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

	// Get a branch by specifying its unique id
	std::shared_ptr<BranchInfo> findBranchByUid(const std::string &uid);
	// Get a branch by specifying its request uri destination.
	std::shared_ptr<BranchInfo> findBranchByDest(const url_t *dest);
	// Get the best candidate among all branches for forwarding its responses.
	std::shared_ptr<BranchInfo> findBestBranch(const int urgentReplies[], bool avoid503And408 = false);
	bool allBranchesAnswered(bool ignore_errors_and_timeouts = false) const;
	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const;
	int getLastResponseCode() const;
	void removeBranch(const std::shared_ptr<BranchInfo> &br);
	const std::list<std::shared_ptr<BranchInfo>> &getBranches() const;
	static bool isUrgent(int code, const int urgentCodes[]);

  public:
	ForkContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, std::shared_ptr<ForkContextConfig> cfg,
				ForkContextListener *listener);
	virtual ~ForkContext() = default;
	// Called by the Router module to create a new branch.
	void addBranch(const std::shared_ptr<RequestSipEvent> &ev, const std::shared_ptr<ExtendedContact> &contact);
	// Called by the router module to notify a cancellation.
	static bool processCancel(const std::shared_ptr<RequestSipEvent> &ev);
	// called by the router module to notify the arrival of a response.
	static bool processResponse(const std::shared_ptr<ResponseSipEvent> &ev);
	// Obtain the ForkContext that manages a transaction.
	static std::shared_ptr<ForkContext> get(const std::shared_ptr<OutgoingTransaction> &tr);
	static std::shared_ptr<ForkContext> get(const std::shared_ptr<IncomingTransaction> &tr);
	// Obtain the BranchInfo corresponding to an outoing transaction
	static std::shared_ptr<BranchInfo> getBranchInfo(const std::shared_ptr<OutgoingTransaction> &tr);
	// Start the processing of the highest priority branches that are not completed yet
	void start();

	void addKey(const std::string &key);
	const std::list<std::string> &getKeys()const;

	/*
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination, then it should return true, false otherwise.
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	**/
	virtual bool onNewRegister(const url_t *dest, const std::string &uid);
	virtual void onPushSent(const std::shared_ptr<OutgoingTransaction> &tr);
	virtual void onPushError(const std::shared_ptr<OutgoingTransaction> &tr, const std::string &errormsg);
	const std::shared_ptr<RequestSipEvent> &getEvent();
	const std::shared_ptr<ForkContextConfig> &getConfig() const {
		return mCfg;
	}
	bool isFinished()const{ return mFinished; };
	static const int sUrgentCodes[];
	static const int sAllCodesUrgent[];
};

}
