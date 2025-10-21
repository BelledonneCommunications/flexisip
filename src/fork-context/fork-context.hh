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

#include <chrono>
#include <memory>
#include <vector>

#include "branch-info.hh"
#include "flexisip/pushnotification/pushnotification-context-observer.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"

namespace flexisip {

class IncomingTransaction;
class OutgoingTransaction;
class RequestSipEvent;
class ResponseSipEvent;
class SipUri;

struct ExtendedContact;

struct ForkContextConfig {
	// Used for "late" forking.
	std::chrono::seconds mDeliveryTimeout{0};
	// Timeout for sending buffered urgent or retryable responses (like '415').
	std::chrono::seconds mUrgentTimeout{5};
	// Timeout for receiving response on current branches.
	std::chrono::seconds mCurrentBranchesTimeout{0};

	bool mForkLate{false};
	bool mForkNoGlobalDecline{false};
	// Treat '603 Declined' as an urgent response, only useful if mForkNoGlobalDecline is 'true'.
	bool mTreatDeclineAsUrgent{false};
	bool mSaveForkMessageEnabled{false};
	// Treat all SIP response codes as urgent replies in the fork mechanism.
	bool mTreatAllErrorsAsUrgent{false};
	// Self-explanatory (example: 110 Push sent, 180 Ringing).
	bool mPermitSelfGeneratedProvisionalResponse{true};
};

class ForkContext : public PushNotificationContextObserver {
public:
	~ForkContext() override = default;

	/**
	 * @param transaction incoming transaction
	 * @param context ForkContext instance to be associated with the transaction
	 */
	static void setFork(const std::shared_ptr<IncomingTransaction>& transaction,
	                    const std::shared_ptr<ForkContext>& context);
	/**
	 * @param transaction incoming transaction
	 * @return ForkContext instance associated with the transaction
	 */
	static std::shared_ptr<ForkContext> getFork(const std::shared_ptr<IncomingTransaction>& transaction);
	/**
	 * @param transaction outgoing transaction
	 * @return ForkContext instance associated with the transaction
	 */
	static std::shared_ptr<ForkContext> getFork(const std::shared_ptr<OutgoingTransaction>& transaction);

	/**
	 * @param ev the request to fork
	 * @param contact contact to fork to
	 * @return the created branch
	 */
	virtual std::shared_ptr<BranchInfo> addBranch(std::unique_ptr<RequestSipEvent>&& ev,
	                                              const std::shared_ptr<ExtendedContact>& contact) = 0;
	/**
	 * @param finalStatusMode fork mode to consider for the final status answer
	 * @return 'true' if all current branches have been answered (see @FinalStatusMode for more information)
	 */
	virtual bool allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const = 0;
	/**
	 * @return 'true' if there are other branches with lower priorities to try
	 */
	virtual bool hasNextBranches() const = 0;
	/**
	 * @brief Send a custom response and cancel all branches if necessary.
	 *
	 * @note MUST be called in case of a fatal error at runtime
	 * @param status status of the custom response to send
	 * @param phrase content of the custom response to send
	 */
	virtual void processInternalError(int status, const char* phrase) = 0;
	/**
	 * @brief Start the processing of the highest priority branches that are not completed yet.
	 */
	virtual void start() = 0;
	/**
	 * @param key record key associated with the ForkContext (see @Record::Key for more information)
	 */
	virtual void addKey(const std::string& key) = 0;
	/**
	 * @return the list of record keys associated with the ForkContext (see @Record::Key for more information)
	 */
	virtual const std::vector<std::string>& getKeys() const = 0;
	/**
	 * @brief Notify the ForkContext that a new register from a potential destination of the fork has just arrived.
	 *
	 * @warning you may not need to process it if another transaction already exists or existed for this contact
	 * @note to use in conjunction with @ForkContextListener
	 * @param dest potential destination of the fork
	 * @param uid unique id of the contact
	 * @param newContact contact that just registered
	 */
	virtual void
	onNewRegister(const SipUri& dest, const std::string& uid, const std::shared_ptr<ExtendedContact>& newContact) = 0;
	/**
	 * @brief Notify branches that a CANCEL request has been received.
	 *
	 * @param ms received CANCEL request
	 */
	virtual void onCancel(const sofiasip::MsgSip& ms) = 0;
	/**
	 * @brief Notify the provided branch that a response has been received.
	 *
	 * @param br branch that received the response
	 * @param event received response
	 */
	virtual void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& event) = 0;
	/**
	 * @brief Process the forwarding of the provided response from a branch.
	 */
	virtual std::unique_ptr<ResponseSipEvent> onSendResponse(std::unique_ptr<ResponseSipEvent>&& event) = 0;
	/**
	 * @return 'true' if the fork is terminated
	 */
	virtual bool isFinished() const = 0;
	/**
	 * @brief Try to send the final response through the incoming transaction.
	 *
	 * @return the branch that was used to answer the caller with the best final response or nullptr if no suitable
	 * final response could be answered for the moment.
	 */
	virtual std::shared_ptr<BranchInfo> tryToSendFinalResponse() = 0;

	/**
	 * @return the event that created the ForkContext
	 */
	virtual RequestSipEvent& getEvent() = 0;
	virtual const ForkContext* getPtrForEquality() const = 0;
	virtual sofiasip::MsgSipPriority getMsgPriority() const = 0;
	virtual const std::shared_ptr<ForkContextConfig>& getConfig() const = 0;
	virtual const std::shared_ptr<IncomingTransaction>& getIncomingTransaction() const = 0;

	/**
	 * @param other other ForkContext to compare with
	 * @return 'true' if the ForkContext pointers are equal (uses ForkContext::getPtrForEquality())
	 */
	bool isEqual(const std::shared_ptr<ForkContext>& other) const {
		return getPtrForEquality() == other->getPtrForEquality();
	}

protected:
	virtual const char* getClassName() const = 0;
};

enum class DispatchStatus {
	DispatchNeeded,
	DispatchNotNeeded,
	PendingTransaction,
};

/**
 * @brief Be notified of major events in the ForkContext lifecycle.
 */
class ForkContextListener {
public:
	virtual ~ForkContextListener() = default;

	/**
	 * @brief Notify a new register and a dispatch is needed for it.
	 *
	 * @param ctx ForkContext that needs a dispatch (add a new branch)
	 * @param newContact contact that just registered
	 * @return the created branch
	 */
	virtual std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>& ctx,
	                                                     const std::shared_ptr<ExtendedContact>& newContact) = 0;
	/**
	 * @brief Notify a new register, but no dispatch is needed for it.
	 *
	 * @param ctx ForkContext that is concerned
	 * @param newContact contact that just registered
	 * @param dest destination of the fork
	 * @param uid unique id of the contact
	 * @param reason why the register is useless (and that no dispatch is needed)
	 */
	virtual void onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
	                                           const std::shared_ptr<ExtendedContact>& newContact,
	                                           const SipUri& dest,
	                                           const std::string& uid,
	                                           DispatchStatus reason) = 0;
	/**
	 * @brief Notify the ForkContext is finished.
	 *
	 * @param ctx ForkContext that is finished
	 */
	virtual void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) = 0;
};

} // namespace flexisip