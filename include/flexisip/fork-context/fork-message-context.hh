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

#include <list>
#include <map>

#include "flexisip/agent.hh"
#include "flexisip/event.hh"
#include "flexisip/fork-context/fork-context-base.hh"
#include "flexisip/fork-context/fork-message-context-db.hh"
#include "flexisip/transaction.hh"

namespace flexisip {

class ForkMessageContext : public ForkContextBase {
public:
	static std::shared_ptr<ForkMessageContext> make(Agent* agent,
	                                                const std::shared_ptr<RequestSipEvent>& event,
	                                                const std::shared_ptr<ForkContextConfig>& cfg,
	                                                const std::weak_ptr<ForkContextListener>& listener,
	                                                const std::weak_ptr<StatPair>& counter);

	static std::shared_ptr<ForkMessageContext> make(Agent* agent,
	                                                const std::shared_ptr<RequestSipEvent>& event,
	                                                const std::shared_ptr<ForkContextConfig>& cfg,
	                                                const std::weak_ptr<ForkContextListener>& listener,
	                                                const std::weak_ptr<StatPair>& counter,
	                                                ForkMessageContextDb& forkFromDb);

	virtual ~ForkMessageContext();

	virtual bool onNewRegister(const SipUri& dest, const std::string& uid, const std::function<void()>& dispatchFunction);
	virtual void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& ev);

	ForkMessageContextDb getDbObject();
	void restoreBranch(const BranchInfoDb& dbBranch);

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContext>& expected);
#endif

protected:
	virtual void onNewBranch(const std::shared_ptr<BranchInfo>& br);
	virtual bool shouldFinish();

private:
	ForkMessageContext(Agent* agent,
	                   const std::shared_ptr<RequestSipEvent>& event,
	                   const std::shared_ptr<ForkContextConfig>& cfg,
	                   const std::weak_ptr<ForkContextListener>& listener,
	                   const std::weak_ptr<StatPair>& counter,
	                   bool isRestored = false);

	void acceptMessage();
	void onAcceptanceTimer();
	void logReceivedFromUserEvent(const std::shared_ptr<RequestSipEvent>& reqEv,
	                              const std::shared_ptr<ResponseSipEvent>& respEv);
	void checkFinished();
	void logDeliveredToUserEvent(const std::shared_ptr<RequestSipEvent>& reqEv,
	                             const std::shared_ptr<ResponseSipEvent>& respEv);

	/**
	 * Timeout after which an answer must be sent through the incoming transaction even if no success response was
	 * received on the outgoing transactions.
	 */
	std::unique_ptr<sofiasip::Timer> mAcceptanceTimer{nullptr};
	int mDeliveredCount;
	/**
	 * Tells if the ForkMessageContext is a message, if false it's a refer.
	 */
	bool mIsMessage;
	/**
	 * Is used in fork late mode with message saved in DB to remember message expiration date.
	 */
	time_t mExpirationDate;
};

} // namespace flexisip
