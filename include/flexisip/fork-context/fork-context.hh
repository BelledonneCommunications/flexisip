/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <memory>
#include <vector>

#include "flexisip/pushnotification/pushnotification-context-observer.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"

namespace flexisip {

class BranchInfo;
class IncomingTransaction;
class OutgoingTransaction;
class RequestSipEvent;
class ResponseSipEvent;
class SipUri;

struct ExtendedContact;

struct ForkContextConfig {
	int mDeliveryTimeout = 0;               /* in seconds, used for "late" forking*/
	std::chrono::seconds mUrgentTimeout{5}; /*timeout for sending buffered urgent or retryable responses (like 415).*/
	std::chrono::seconds mPushResponseTimeout{0}; /*timeout for receiving response to push */
	int mCurrentBranchesTimeout = 0;              /*timeout for receiving response on current branches*/
	bool mForkLate = false;
	bool mSaveForkMessageEnabled = false;
	bool mTreatAllErrorsAsUrgent = false; /*treat all SIP response code as urgent replies in the fork mechanism.*/
	bool mForkNoGlobalDecline = false;
	bool mTreatDeclineAsUrgent =
	    false; /*treat 603 declined as a urgent response, only useful is mForkNoGlobalDecline==true*/
	bool mPermitSelfGeneratedProvisionalResponse = true; /* Self explicit. Ex: 110 Push sent, 180 Ringing*/
};

class ForkContext : public PushNotificationContextObserver {
public:
	virtual ~ForkContext() = default;

	// Obtain the ForkContext that manages a transaction.
	static std::shared_ptr<ForkContext> getFork(const std::shared_ptr<IncomingTransaction>& tr);
	static std::shared_ptr<ForkContext> getFork(const std::shared_ptr<OutgoingTransaction>& tr);
	// Set the ForkContext managed by an incoming transaction.
	static void setFork(const std::shared_ptr<IncomingTransaction>& tr, const std::shared_ptr<ForkContext>& fork);

	// Called by the router module to notify a cancellation.
	static void processCancel(const std::shared_ptr<RequestSipEvent>& ev);
	// called by the router module to notify the arrival of a response.
	static bool processResponse(const std::shared_ptr<ResponseSipEvent>& ev);

	bool isEqual(const std::shared_ptr<ForkContext>& other) const {
		return getPtrForEquality() == other->getPtrForEquality();
	}

	// Called by the Router module to create a new branch.
	virtual std::shared_ptr<BranchInfo> addBranch(const std::shared_ptr<RequestSipEvent>& ev,
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
	virtual const std::vector<std::string>& getKeys() const = 0;

	/**
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination he can call
	 * ForkContextListener::onDispatchNeeded, call ForkContextListener::onUselessRegisterNotification otherwise.
	 *
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	 */
	virtual void
	onNewRegister(const SipUri& dest, const std::string& uid, const std::shared_ptr<ExtendedContact>& newContact) = 0;
	// Notifies the cancellation of the fork process.
	virtual void onCancel(const std::shared_ptr<RequestSipEvent>& ev) = 0;
	// Notifies the arrival of a new response on a given branch
	virtual void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) = 0;
	virtual const std::shared_ptr<RequestSipEvent>& getEvent() = 0;
	virtual const std::shared_ptr<ForkContextConfig>& getConfig() const = 0;
	virtual bool isFinished() const = 0;
	virtual void checkFinished() = 0;
	virtual sofiasip::MsgSipPriority getMsgPriority() const = 0;
	virtual const ForkContext* getPtrForEquality() const = 0;

protected:
	// Protected methods
	std::string errorLogPrefix() const;
	std::string logPrefix() const;
	virtual const char* getClassName() const = 0;
};

enum class DispatchStatus {
	DispatchNeeded,
	DispatchNotNeeded,
	PendingTransaction,
};

class ForkContextListener {
public:
	virtual ~ForkContextListener() = default;

	virtual void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) = 0;

	/**
	 * Called when a fork context need a dispatch for specific contact.
	 */
	virtual std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>& ctx,
	                                                     const std::shared_ptr<ExtendedContact>& newContact) = 0;

	/**
	 * Called when onNewRegister was called on a fork and that no dispatch was needed for this contact.
	 */
	virtual void onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
	                                           const std::shared_ptr<ExtendedContact>& newContact,
	                                           const SipUri& dest,
	                                           const std::string& uid,
	                                           const DispatchStatus reason) = 0;
};

} // namespace flexisip
