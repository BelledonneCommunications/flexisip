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

#include <list>
#include <map>

#include "flexisip/agent.hh"
#include "flexisip/event.hh"
#include "flexisip/fork-context/fork-context-base.hh"
#include "flexisip/transaction.hh"

namespace flexisip {

class ForkMessageContext : public ForkContextBase {
public:
	static std::shared_ptr<ForkMessageContext> make(Agent* agent, const std::shared_ptr<RequestSipEvent>& event,
	                                                const std::shared_ptr<ForkContextConfig>& cfg,
	                                                const std::weak_ptr<ForkContextListener>& listener,
	                                                const std::weak_ptr<StatPair>& counter);
	virtual ~ForkMessageContext();

	virtual bool onNewRegister(const url_t* url, const std::string& uid);
	virtual void onResponse(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &ev);

protected:
	virtual void onNewBranch(const std::shared_ptr<BranchInfo> &br);
	virtual bool shouldFinish();

private:
	ForkMessageContext(Agent* agent, const std::shared_ptr<RequestSipEvent>& event,
	                   const std::shared_ptr<ForkContextConfig>& cfg,
	                   const std::weak_ptr<ForkContextListener>& listener, const std::weak_ptr<StatPair>& counter);
	static void sOnAcceptanceTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	void acceptMessage();
	void onAcceptanceTimer();
	void logReceivedFromUserEvent(const std::shared_ptr<RequestSipEvent> &reqEv, const std::shared_ptr<ResponseSipEvent> &respEv);
	void checkFinished();
	void logDeliveredToUserEvent(const std::shared_ptr<RequestSipEvent> &reqEv, const std::shared_ptr<ResponseSipEvent> &respEv);

	su_timer_t
	    *mAcceptanceTimer; /*timeout after which an answer must be sent through the incoming transaction even if no
	                                             success response was received on the outgoing transactions*/
	static const int sAcceptanceTimeout = 20; /* this must be less than the transaction time (32 seconds)*/
	int mDeliveredCount;
	bool mIsMessage; /* tells if the ForkMessageContext is a message, if false it's a refer */
};

}
