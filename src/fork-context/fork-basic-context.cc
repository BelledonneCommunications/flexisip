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

#include <algorithm>
#include <flexisip/common.hh>
#include <flexisip/fork-context/fork-basic-context.hh>
#include <flexisip/registrardb.hh>
#include <sofia-sip/sip_status.h>

using namespace std;
using namespace flexisip;

shared_ptr<ForkBasicContext> ForkBasicContext::make(Agent* agent, const shared_ptr<RequestSipEvent>& event,
                                                    const shared_ptr<ForkContextConfig>& cfg,
                                                    const weak_ptr<ForkContextListener>& listener,
                                                    const weak_ptr<StatPair>& counter) {
	const shared_ptr<ForkBasicContext> shared{new ForkBasicContext(agent, event, cfg, listener, counter)};
	return shared;
}

ForkBasicContext::ForkBasicContext(Agent* agent, const shared_ptr<RequestSipEvent>& event,
                                   const shared_ptr<ForkContextConfig>& cfg,
                                   const weak_ptr<ForkContextListener>& listener, const weak_ptr<StatPair>& counter)
    : ForkContextBase(agent, event, cfg, listener, counter) {
	LOGD("New ForkBasicContext %p", this);
	mDecisionTimer = make_unique<sofiasip::Timer>(mAgent->getRoot(), 20000);
	// start the acceptance timer immediately
	mDecisionTimer->set([this]() { onDecisionTimer(); });
}

ForkBasicContext::~ForkBasicContext() {
	LOGD("Destroy ForkBasicContext %p", this);
}

void ForkBasicContext::onResponse(const shared_ptr<BranchInfo>& br, const shared_ptr<ResponseSipEvent>& event) {
	int code = br->getStatus();
	if (code >= 200) {
		if (code < 300) {
			forwardResponse(br);
			mDecisionTimer.reset(nullptr);
		} else {
			if (allBranchesAnswered()) {
				finishIncomingTransaction();
			}
		}
	}
}

void ForkBasicContext::finishIncomingTransaction() {
	mDecisionTimer.reset(nullptr);

	shared_ptr<BranchInfo> best = findBestBranch(sUrgentCodes);
	if (best == nullptr) {
		forwardCustomResponse(SIP_408_REQUEST_TIMEOUT);
	} else {
		forwardResponse(best);
	}
}

void ForkBasicContext::onDecisionTimer() {
	LOGD("ForkBasicContext::onDecisionTimer()");
	finishIncomingTransaction();
}

bool ForkBasicContext::onNewRegister(const url_t* url, const string& uid) {
	return false;
}

void ForkBasicContext::processInternalError(int status, const char* phrase) {
	mDecisionTimer.reset(nullptr);
	ForkContextBase::processInternalError(status, phrase);
}
