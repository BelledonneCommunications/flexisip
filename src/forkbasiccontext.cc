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
#include "forkbasiccontext.hh"
#include "registrardb.hh"
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>

using namespace ::std;

ForkBasicContext::ForkBasicContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		ForkContext(agent, event,cfg,listener) {
	LOGD("New ForkBasicContext %p", this);
	mDecisionTimer=NULL;
	//start the acceptance timer immediately
	mDecisionTimer=su_timer_create(su_root_task(mAgent->getRoot()), 0);
	su_timer_set_interval(mDecisionTimer, &ForkBasicContext::sOnDecisionTimer, this, (su_duration_t)20000);
}

ForkBasicContext::~ForkBasicContext() {
	if (mDecisionTimer)
		su_timer_destroy(mDecisionTimer);
	LOGD("Destroy ForkBasicContext %p", this);
}

void ForkBasicContext::onResponse(const shared_ptr<BranchInfo> &br, const shared_ptr<ResponseSipEvent> &event) {
	int code=br->getStatus();
	if (code>=200){
		if (code<300){
			forwardResponse(br);
			if (mDecisionTimer){
				su_timer_destroy(mDecisionTimer);
				mDecisionTimer=NULL;
			}
		}else{
			if (allBranchesAnswered()){
				finishIncomingTransaction();
			}
		}
	}
}

void ForkBasicContext::finishIncomingTransaction(){
	if (mDecisionTimer){
		su_timer_destroy(mDecisionTimer);
		mDecisionTimer=NULL;
	}
	shared_ptr<BranchInfo> best=findBestBranch(sUrgentCodes);
	if (best==NULL) {
		// Create response
		shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
		if (msgsip){
			shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
			forwardResponse(ev);
		}
	}else{
		forwardResponse(best);
	}
}

void ForkBasicContext::onDecisionTimer(){
	LOGD("ForkBasicContext::onDecisionTimer()");
	finishIncomingTransaction();
}

void ForkBasicContext::sOnDecisionTimer(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg){
	static_cast<ForkBasicContext*>(arg)->onDecisionTimer();
}

bool ForkBasicContext::onNewRegister(const url_t *url, const string &uid){
	return false;
}

