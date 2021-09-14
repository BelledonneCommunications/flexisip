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
#include "flexisip/registrardb.hh"
#include "flexisip/transaction.hh"

namespace flexisip {

class BranchInfo;

struct ForkContextConfig {
	int mDeliveryTimeout = 0;        /* in seconds, used for "late" forking*/
	int mUrgentTimeout = 5;          /*timeout for sending buffered urgent or retryable reponses (like 415).*/
	int mPushResponseTimeout = 0;    /*timeout for receiving response to push */
	int mCurrentBranchesTimeout = 0; /*timeout for receiving response on current branches*/
	bool mForkLate = false;
	bool mTreatAllErrorsAsUrgent = false; /*treat all SIP response code as urgent replies in the fork mechanism.*/
	bool mForkNoGlobalDecline = false;
	bool mTreatDeclineAsUrgent =
	    false; /*treat 603 declined as a urgent response, only useful is mForkNoGlobalDecline==true*/
	bool mPermitSelfGeneratedProvisionalResponse = true; /* Self explicit. Ex: 110 Push sent, 180 Ringing*/
};

class ForkContext {
public:
	// Obtain the ForkContext that manages a transaction.
	static std::shared_ptr<ForkContext> getFork(const std::shared_ptr<IncomingTransaction>& tr);
	static std::shared_ptr<ForkContext> getFork(const std::shared_ptr<OutgoingTransaction>& tr);
	// Set the ForkContext managed by an incoming transaction.
	static void setFork(const std::shared_ptr<IncomingTransaction>& tr, const std::shared_ptr<ForkContext>& fork);

	// Called by the router module to notify a cancellation.
	static void processCancel(const std::shared_ptr<RequestSipEvent>& ev);
	// called by the router module to notify the arrival of a response.
	static bool processResponse(const std::shared_ptr<ResponseSipEvent>& ev);

	// Called by the Router module to create a new branch.
	virtual void addBranch(const std::shared_ptr<RequestSipEvent>& ev,
	                       const std::shared_ptr<ExtendedContact>& contact) = 0;
	virtual bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const = 0;
	// Request if the fork has other branches with lower priorities to try
	virtual bool hasNextBranches() const = 0;
	/**
	 * Called when a fatal internal error is thrown in Flexisip. Send a custom response and cancel all branches if
	 * necessary.
	 * @param status The status of the custom response to send.
	 * @param phrase The content of the custom response to send.
	 */
	virtual void processInternalError(int status, const char* phrase) = 0;
	// Start the processing of the highest priority branches that are not completed yet
	virtual void start() = 0;

	virtual void addKey(const std::string& key) = 0;
	virtual const std::list<std::string>& getKeys() const = 0;

	/*
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination, then it should return true, false otherwise.
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	 **/
	virtual bool onNewRegister(const url_t* dest, const std::string& uid) = 0;
	virtual void onPushSent(const std::shared_ptr<OutgoingTransaction>& tr) = 0;
	virtual void onPushError(const std::shared_ptr<OutgoingTransaction>& tr, const std::string& errormsg) = 0;
	// Notifies the cancellation of the fork process.
	virtual void onCancel(const std::shared_ptr<RequestSipEvent>& ev) = 0;
	// Notifies the arrival of a new response on a given branch
	virtual void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) = 0;
	virtual const std::shared_ptr<RequestSipEvent>& getEvent() = 0;
	virtual const std::shared_ptr<ForkContextConfig>& getConfig() const = 0;
	virtual bool isFinished() const = 0;
};

class ForkContextListener {
public:
	virtual ~ForkContextListener() = default;
	virtual void onForkContextFinished(std::shared_ptr<ForkContext> ctx) = 0;
};

} // namespace flexisip
