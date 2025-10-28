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

#include "agent.hh"
#include "flexisip/event.hh"
#include "fork-context-base.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/message-kind.hh"
#include "fork-message-context-db.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {

/**
 * @brief Handle the forking of SIP chat messages (MESSAGE requests). It manages the branches of the call and processes
 * responses from them.
 */
class ForkMessageContext : public ForkContextBase {
public:
	~ForkMessageContext() override;

	template <typename... Args>
	static std::shared_ptr<ForkMessageContext> make(Args&&... args) {
		return std::shared_ptr<ForkMessageContext>{new ForkMessageContext{std::forward<Args>(args)...}};
	}

	static std::shared_ptr<ForkMessageContext> restore(ForkMessageContextDb& forkContextFromDb,
	                                                   const std::weak_ptr<ForkContextListener>& forkContextListener,
	                                                   const std::weak_ptr<InjectorListener>& injectorListener,
	                                                   Agent* agent,
	                                                   const std::shared_ptr<ForkContextConfig>& config,
	                                                   const std::weak_ptr<StatPair>& counter);

	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;

	void start() override;
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) override;

	ForkMessageContextDb getDbObject();
	void restoreBranch(const BranchInfoDb& dbBranch);

	time_t getExpirationDate() const {
		return mExpirationDate;
	}

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContext>& expected);
#endif

protected:
	static constexpr std::string_view kClassName{"ForkMessageContext"};
	static constexpr std::string_view kEventIdHeader{"X-fs-event-id"};

	const char* getClassName() const override;

	void onNewBranch(const std::shared_ptr<BranchInfo>& br) override;
	bool shouldFinish() override;

private:
	ForkMessageContext(std::unique_ptr<RequestSipEvent>&& event,
	                   sofiasip::MsgSipPriority priority,
	                   const MessageKind& kind,
	                   bool isRestored,
	                   const std::weak_ptr<ForkContextListener>& forkContextListener,
	                   const std::weak_ptr<InjectorListener>& injectorListener,
	                   AgentInterface* agent,
	                   const std::shared_ptr<ForkContextConfig>& config,
	                   const std::weak_ptr<StatPair>& counter);

	/**
	 * @brief Accept the MESSAGE request (send '202 Accepted') if no good response has been received on any branch.
	 */
	void acceptMessage();
	/**
	 * @brief Accept the MESSAGE request when the acceptance timer expires (see @ForkMessageContext::acceptMessage).
	 */
	void onAcceptanceTimer();
	/**
	 * @brief Send the event log for this response to the sender.
	 *
	 * @param reqEv initial request
	 * @param respEv received response
	 */
	void logResponseToSender(const RequestSipEvent& reqEv, ResponseSipEvent& respEv) const;
	/**
	 * @brief Send the event log for this response to the recipient.
	 *
	 * @param br branch that received the response
	 * @param respEv received response
	 */
	void logResponseFromRecipient(const BranchInfo& br, ResponseSipEvent& respEv);

	// Timeout after which an answer must be sent through the incoming transaction even if no success response was
	// received on the outgoing transactions.
	std::unique_ptr<sofiasip::Timer> mAcceptanceTimer{nullptr};
	int mDeliveredCount;
	// Type of SIP MESSAGE this context is handling.
	MessageKind mKind;
	// Used in fork late mode with a message saved in DB to remember the message expiration date.
	time_t mExpirationDate;
	std::string mLogPrefix;
};

} // namespace flexisip