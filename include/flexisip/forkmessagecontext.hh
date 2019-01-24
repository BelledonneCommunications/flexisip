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
#include <flexisip/forkcontext.hh>

#include <list>
#include <map>

namespace flexisip {

class ForkMessageContext : public ForkContext {
  private:
	su_timer_t
		*mAcceptanceTimer; /*timeout after which an answer must be sent through the incoming transaction even if no
							  success response was received on the outgoing transactions*/
	static const int sAcceptanceTimeout = 20; /* this must be less than the transaction time (32 seconds)*/
	int mDeliveredCount;
	bool mIsMessage; /* tells if the ForkMessageContext is a message, if false it's a refer */

  public:
	ForkMessageContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event,
					   std::shared_ptr<ForkContextConfig> cfg, ForkContextListener *listener);
	virtual ~ForkMessageContext();

  protected:
	virtual bool onNewRegister(const url_t *url, const std::string &uid);
	virtual void onNewBranch(const std::shared_ptr<BranchInfo> &br);
	virtual void onResponse(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &ev);
	virtual bool shouldFinish();

  private:
	static void sOnAcceptanceTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	void acceptMessage();
	void onAcceptanceTimer();
	void logReceivedFromUserEvent(const std::shared_ptr<ResponseSipEvent> &ev);
	void checkFinished();
	void logDeliveredToUserEvent(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &event);
};

}
