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

#include "flexisip/agent.hh"
#include "flexisip/event.hh"
#include "flexisip/forkcontext.hh"
#include "flexisip/transaction.hh"
#include "flexisip/utils/timer.hh"

namespace flexisip {

enum class ForkStatus {
	 AcceptedElsewhere,
	 DeclineElsewhere,
	 Standard
};

class ForkCallContext : public ForkContext {
  public:
	ForkCallContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, std::shared_ptr<ForkContextConfig> cfg,
					ForkContextListener *listener, std::weak_ptr<StatPair> counter);
	~ForkCallContext();

	void sendResponse(int status, char const *phrase);

	bool isCompleted() const;
	bool isRingingSomewhere() const;

	void onPushSent(const std::shared_ptr<OutgoingTransaction> &tr) override;
	void onPushError(const std::shared_ptr<OutgoingTransaction> &tr, const std::string &errormsg) override;

  protected:
	void onResponse(const std::shared_ptr<BranchInfo> &br, const std::shared_ptr<ResponseSipEvent> &event) override;
	bool onNewRegister(const url_t *url, const std::string &uid) override;
	void onCancel(const std::shared_ptr<RequestSipEvent> &ev) override;

  private:
	const int *getUrgentCodes();
	void onShortTimer();
	void onPushTimer();
	void onLateTimeout() override;
	void cancelOthers(const std::shared_ptr<BranchInfo> &br, sip_t* received_cancel);
	void cancelOthersWithStatus(const std::shared_ptr<BranchInfo> &br, ForkStatus status);
	void logResponse(const std::shared_ptr<ResponseSipEvent> &ev);
	static const int sUrgentCodesWithout603[];

	std::unique_ptr<sofiasip::Timer> mShortTimer{}; // optionaly used to send retryable responses
	std::unique_ptr<sofiasip::Timer> mPushTimer{}; // used to track push responses
	std::shared_ptr<CallLog> mLog{};
	bool mCancelled = false;
	int mActivePushes = 0;
};

}
