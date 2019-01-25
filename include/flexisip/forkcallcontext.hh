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

namespace flexisip {

enum FlexisipForkStatus {FlexisipForkAcceptedElsewhere, FlexisipForkDeclineElsewhere, FlexisipForkStandard};

class ForkCallContext : public ForkContext {
  private:
	su_timer_t *mShortTimer; // optionaly used to send retryable responses
	su_timer_t *mPushTimer; // used to track push responses
	std::shared_ptr<CallLog> mLog;
	bool mCancelled;

  public:
	ForkCallContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, std::shared_ptr<ForkContextConfig> cfg,
					ForkContextListener *listener);
	~ForkCallContext();
	void sendResponse(int status, char const *phrase);
	bool isCompleted() const;
	void onPushInitiated(const std::string &key);
	void onPushError(const std::string &key, const std::string &errormsg);

  protected:
	virtual void onResponse(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &event);
	virtual bool onNewRegister(const url_t *url, const std::string &uid);
	virtual void onCancel(const std::shared_ptr<RequestSipEvent> &ev);

  private:
	bool isRingingSomewhere()const;
	const int *getUrgentCodes();
	void onShortTimer();
	void onPushTimer();
	void onLateTimeout();
	void cancelOthers(const std::shared_ptr<BranchInfo> &br, sip_t* received_cancel);
	void cancelOthersWithStatus(const std::shared_ptr<BranchInfo> &br, FlexisipForkStatus status);
	void logResponse(const std::shared_ptr<ResponseSipEvent> &ev);
	static void sOnShortTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	static void sOnPushTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	int mActivePushes;
	static const int sUrgentCodesWithout603[];
};

}