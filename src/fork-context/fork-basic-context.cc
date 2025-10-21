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

#include "fork-basic-context.hh"

#include "agent.hh"
#include "fork-context/branch-info.hh"

using namespace std;
using namespace flexisip;

ForkBasicContext::ForkBasicContext(std::unique_ptr<RequestSipEvent>&& event,
                                   sofiasip::MsgSipPriority priority,
                                   const std::weak_ptr<ForkContextListener>& forkContextListener,
                                   const std::weak_ptr<InjectorListener>& injectorListener,
                                   AgentInterface* agent,
                                   const std::shared_ptr<ForkContextConfig>& config,
                                   const std::weak_ptr<StatPair>& counter)
    : ForkContextBase{agent, config, injectorListener, forkContextListener, std::move(event), counter, priority} {
	mDecisionTimer = make_unique<sofiasip::Timer>(mAgent->getRoot(), 20s);
	// start the acceptance timer immediately
	mDecisionTimer->set([this]() { onDecisionTimer(); });
	mLogPrefix = LogManager::makeLogPrefixForInstance(this, "ForkBasicContext");
	LOGD << "New instance";
}

ForkBasicContext::~ForkBasicContext() {
	LOGD << "Destroy instance";
}

void ForkBasicContext::onResponse(const shared_ptr<BranchInfo>& br, ResponseSipEvent& event) {
	ForkContextBase::onResponse(br, event);

	int code = br->getStatus();
	if (code >= 200) {
		if (code < 300) {
			br->sendResponse(mIncoming != nullptr);
			mDecisionTimer.reset(nullptr);
		} else {
			if (allBranchesAnswered(FinalStatusMode::RFC)) {
				finishIncomingTransaction();
			}
		}
	}
}

void ForkBasicContext::finishIncomingTransaction() {
	mDecisionTimer.reset(nullptr);

	// mIncoming can be already terminated if a previous 200 response was received
	if (mIncoming) {
		shared_ptr<BranchInfo> best = findBestBranch();
		if (best == nullptr) {
			sendCustomResponse(SIP_408_REQUEST_TIMEOUT);
		} else {
			best->sendResponse(mIncoming != nullptr);
		}
	}
}

void ForkBasicContext::onDecisionTimer() {
	LOGD << "Running " << __func__;
	finishIncomingTransaction();
}

void ForkBasicContext::processInternalError(int status, const char* phrase) {
	mDecisionTimer.reset(nullptr);
	ForkContextBase::processInternalError(status, phrase);
}