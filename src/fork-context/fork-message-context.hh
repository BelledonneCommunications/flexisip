/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <list>
#include <map>
#include <memory>

#include "flexisip/event.hh"
#include "flexisip/module-router.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context-base.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/message-kind.hh"
#include "fork-message-context-db.hh"
#include "registrar/extended-contact.hh"

namespace flexisip {
class ModuleRouter;

class ForkMessageContext : public ForkContextBase {
public:
	static std::shared_ptr<ForkMessageContext> make(const std::shared_ptr<ModuleRouter>& router,
	                                                const std::weak_ptr<ForkContextListener>& listener,
	                                                std::unique_ptr<RequestSipEvent>&& event,
	                                                sofiasip::MsgSipPriority priority);

	static std::shared_ptr<ForkMessageContext> make(const std::shared_ptr<ModuleRouter> router,
	                                                const std::weak_ptr<ForkContextListener>& listener,
	                                                ForkMessageContextDb& forkFromDb);

	virtual ~ForkMessageContext();

	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) override;

	ForkMessageContextDb getDbObject();
	void restoreBranch(const BranchInfoDb& dbBranch);
	time_t getExpirationDate() const {
		return mExpirationDate;
	}
	void start() override;

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContext>& expected);
#endif

	static constexpr auto kEventIdHeader = "X-fs-event-id";

protected:
	void onNewBranch(const std::shared_ptr<BranchInfo>& br) override;
	bool shouldFinish() override;

	static constexpr auto CLASS_NAME = "ForkMessageContext";
	const char* getClassName() const override {
		return CLASS_NAME;
	};

private:
	ForkMessageContext(const std::shared_ptr<ModuleRouter>& router,
	                   const std::weak_ptr<ForkContextListener>& listener,
	                   std::unique_ptr<RequestSipEvent>&& event,
	                   sofiasip::MsgSipPriority msgPriority,
	                   bool isRestored = false);

	void acceptMessage();
	void onAcceptanceTimer();
	void logResponseToSender(const RequestSipEvent& reqEv, ResponseSipEvent& respEv);
	void logResponseFromRecipient(const BranchInfo& br, ResponseSipEvent& event);

	/**
	 * Timeout after which an answer must be sent through the incoming transaction even if no success response was
	 * received on the outgoing transactions.
	 */
	std::unique_ptr<sofiasip::Timer> mAcceptanceTimer{nullptr};
	int mDeliveredCount;
	// What kind of SIP MESSAGE is this ForkContext handling?
	MessageKind mKind;
	/**
	 * Is used in fork late mode with message saved in DB to remember message expiration date.
	 */
	time_t mExpirationDate;
    std::string mLogPrefix;
};

} // namespace flexisip
