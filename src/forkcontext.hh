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

#ifndef forkcontext_hh
#define forkcontext_hh

#include "agent.hh"
#include "event.hh"
#include "transaction.hh"
#include "registrardb.hh"

class ForkContextConfig {
  public:
	ForkContextConfig();
	int mDeliveryTimeout;	 /* in seconds, used for "late" forking*/
	int mUrgentTimeout;		  /*timeout for sending buffered urgent or retryable reponses (like 415).*/
	int mPushResponseTimeout; /*timeout for receiving response to push */
	bool mForkLate;
	bool mTreatAllErrorsAsUrgent; /*treat all SIP response code as urgent replies in the fork mechanism.*/
	bool mForkNoGlobalDecline;
	bool mTreatDeclineAsUrgent; /*treat 603 declined as a urgent response, only useful is mForkNoGlobalDecline==true*/
	bool mRemoveToTag;			/*workaround buggy OVH which wrongly terminates wrong call*/
};

class ForkContext;

class ForkContextListener {
  public:
	virtual ~ForkContextListener();
	virtual void onForkContextFinished(std::shared_ptr<ForkContext> ctx) = 0;
};

class BranchInfo {
  public:
	BranchInfo(std::shared_ptr<ForkContext> ctx) : mForkCtx(ctx) {
	}
	virtual ~BranchInfo();
	virtual void clear();
	int getStatus() {
		if (mLastResponse)
			return mLastResponse->getMsgSip()->getSip()->sip_status->st_status;
		return 0;
	}
	std::shared_ptr<ForkContext> mForkCtx;
	std::string mUid;
	std::shared_ptr<RequestSipEvent> mRequest;
	std::shared_ptr<OutgoingTransaction> mTransaction;
	std::shared_ptr<ResponseSipEvent> mLastResponse;
	std::shared_ptr<ExtendedContact> mContact;
};

class ForkContext : public std::enable_shared_from_this<ForkContext> {
  private:
	static void __timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	static void sOnFinished(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	ForkContextListener *mListener;
	std::list<std::shared_ptr<BranchInfo>> mBranches;
	std::string mKey;
	void init();
	void processLateTimeout();
	std::shared_ptr<BranchInfo> _findBestBranch(const int urgentReplies[], bool ignore503And408);

  protected:
	Agent *mAgent;
	std::shared_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<ResponseSipEvent> mLastResponseSent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	std::shared_ptr<ForkContextConfig> mCfg;
	std::shared_ptr<ForkContext> mSelf;
	su_timer_t *mLateTimer;
	su_timer_t *mFinishTimer;
	// Mark the fork process as terminated. The real destruction is performed asynchrously, in next main loop iteration.
	void setFinished();
	// Used by derived class to allocate a derived type of BranchInfo if necessary.
	virtual std::shared_ptr<BranchInfo> createBranchInfo();
	// Notifies derived class of the creation of a new branch
	virtual void onNewBranch(const std::shared_ptr<BranchInfo> &br);
	// Notifies the cancellation of the fork process.
	virtual void onCancel();
	// Notifies the arrival of a new response on a given branch
	virtual void onResponse(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &event) = 0;
	// Notifies the expiry of the final fork timeout.
	virtual void onLateTimeout();
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
	int getLastResponseCode() const;
	void removeBranch(const std::shared_ptr<BranchInfo> &br);
	const std::list<std::shared_ptr<BranchInfo>> &getBranches()const;
	static bool isUrgent(int code, const int urgentCodes[]);

  public:
	ForkContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, std::shared_ptr<ForkContextConfig> cfg,
				ForkContextListener *listener);
	virtual ~ForkContext();
	// Called by the Router module to create a new branch.
	void addBranch(const std::shared_ptr<RequestSipEvent> &ev, const shared_ptr<ExtendedContact> &contact);
	// Called by the router module to notify a cancellation.
	static bool processCancel(const std::shared_ptr<RequestSipEvent> &ev);
	// called by the router module to notify the arrival of a response.
	static bool processResponse(const std::shared_ptr<ResponseSipEvent> &ev);
	// Obtain the ForkContext that manages a transaction.
	static std::shared_ptr<ForkContext> get(const std::shared_ptr<OutgoingTransaction> &tr);
	static std::shared_ptr<ForkContext> get(const std::shared_ptr<IncomingTransaction> &tr);
	
	void setKey(std::string key);
	std::string getKey();

	/*
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination, then it should return true, false otherwise.
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	**/
	virtual bool onNewRegister(const url_t *dest, const std::string &uid);
	const std::shared_ptr<RequestSipEvent> &getEvent();
	const std::shared_ptr<ForkContextConfig> &getConfig() const {
		return mCfg;
	}
	static const int sUrgentCodes[];
	static const int sAllCodesUrgent[];
};

#endif /* forkcontext_hh */
