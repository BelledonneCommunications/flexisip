/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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
		ForkContext(agent, event,cfg,listener), mDeliveredCount(0) {
	LOGD("New ForkBasicContext %p", this);
	mDecisionTimer=NULL;
}

ForkBasicContext::~ForkBasicContext() {
	if (mDecisionTimer)
		su_timer_destroy(mDecisionTimer);
	LOGD("Destroy ForkBasicContext %p", this);
}

void ForkBasicContext::forward(const shared_ptr<ResponseSipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();
	
	if (sip->sip_status->st_status >= 200 ) {
		if (mDeliveredCount>1){
			/*should only transfer one response*/
			ev->setIncomingAgent(shared_ptr<IncomingAgent>());
		}
		mDeliveredCount++;
		checkFinished();
	}
}

void ForkBasicContext::checkFinished(){
	return ForkContext::checkFinished();
}

void ForkBasicContext::onRequest(const shared_ptr<IncomingTransaction> &transaction, shared_ptr<RequestSipEvent> &event) {
	
}

void ForkBasicContext::store(shared_ptr<ResponseSipEvent> &event) {
	bool best = true;

	if (mBestResponse != NULL) {
		if (mBestResponse->getMsgSip()->getSip()->sip_status->st_status < event->getMsgSip()->getSip()->sip_status->st_status) {
			best = false;
		}
	}
	// Save
	if (best) {
		mBestResponse = make_shared<ResponseSipEvent>(event); // Copy event
		mBestResponse->suspendProcessing();
	}
	// Don't forward
	event->setIncomingAgent(shared_ptr<IncomingAgent>());
}

void ForkBasicContext::onResponse(const shared_ptr<OutgoingTransaction> &transaction, shared_ptr<ResponseSipEvent> &event) {
	event->setIncomingAgent(mIncoming);
	const shared_ptr<MsgSip> &ms = event->getMsgSip();
	
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_status != NULL) {
		LOGD("Fork: outgoingCallback %d", sip->sip_status->st_status);
		
		if (sip->sip_status->st_status > 100 && sip->sip_status->st_status < 300) {
			forward(event);
		} else {
			store(event);
		}
	}
}

void ForkBasicContext::finishIncomingTransaction(){
	if (mIncoming != NULL && mDeliveredCount==0) {
		if (mBestResponse == NULL) {
			// Create response
			shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
			shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
			ev->setIncomingAgent(mIncoming);
			mAgent->sendResponseEvent(ev);
		} else {
			mAgent->injectResponseEvent(mBestResponse);
		}
	}
	if (mDecisionTimer){
		su_timer_destroy(mDecisionTimer);
		mDecisionTimer=NULL;
	}
	mBestResponse.reset();
	mIncoming.reset();
}

void ForkBasicContext::onDecisionTimer(){
	LOGD("ForkBasicContext::onDecisionTimer()");
	finishIncomingTransaction();
}

void ForkBasicContext::sOnDecisionTimer(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg){
	static_cast<ForkBasicContext*>(arg)->onDecisionTimer();
}


void ForkBasicContext::onNew(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onNew(transaction);
	//start the acceptance timer immediately
	mDecisionTimer=su_timer_create(su_root_task(mAgent->getRoot()), 0);
	su_timer_set_interval(mDecisionTimer, &ForkBasicContext::sOnDecisionTimer, this, (su_duration_t)20000);
}

void ForkBasicContext::onDestroy(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onDestroy(transaction);
}

void ForkBasicContext::onNew(const shared_ptr<OutgoingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

void ForkBasicContext::onDestroy(const shared_ptr<OutgoingTransaction> &transaction) {
	if (mOutgoings.size() == 1) {
		finishIncomingTransaction();
	}
	ForkContext::onDestroy(transaction);
}

bool ForkBasicContext::onNewRegister(const sip_contact_t *ctt){
	return false;
}

