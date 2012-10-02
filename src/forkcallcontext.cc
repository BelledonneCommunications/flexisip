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

#include "forkcallcontext.hh"
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>

using namespace ::std;

ForkCallContext::ForkCallContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		ForkContext(agent, event,cfg, listener), mFinal(0),mCancelled(false) {
	LOGD("New ForkCallContext %p", this);
	
}

ForkCallContext::~ForkCallContext() {
	LOGD("Destroy ForkCallContext %p", this);
}

void ForkCallContext::cancel() {
	mCancelled=true;
	cancelOthers();
}

void ForkCallContext::forward(const shared_ptr<SipEvent> &ev, bool force) {
	sip_t *sip = ev->getMsgSip()->getSip();
	bool fakeSipEvent = (mFinal > 0 && !force) || mIncoming == NULL;

	if (mCfg->mForkOneResponse) { // TODO: respect RFC 3261 16.7.5
		if (sip->sip_status->st_status == 183 || sip->sip_status->st_status == 180) {
			auto it = find(mForwardResponses.begin(), mForwardResponses.end(), sip->sip_status->st_status);
			if (it != mForwardResponses.end()) {
				fakeSipEvent = true;
			} else {
				mForwardResponses.push_back(sip->sip_status->st_status);
			}
		}
	}

	if (fakeSipEvent) {
		ev->setIncomingAgent(shared_ptr<IncomingAgent>());
	}

	if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 700) {
		++mFinal;
	}
}

void ForkCallContext::decline(const shared_ptr<OutgoingTransaction> &transaction, shared_ptr<ResponseSipEvent> &ev) {
	if (!mCfg->mForkNoGlobalDecline) {
		cancelOthers(transaction);

		forward(ev);
	} else {
		if (mOutgoings.size() != 1) {
			ev->setIncomingAgent(shared_ptr<IncomingAgent>());
		} else {
			forward(ev);
		}
	}
}

void ForkCallContext::cancelOthers(const shared_ptr<OutgoingTransaction> &transaction) {
	if (mFinal == 0) {
		for (list<shared_ptr<OutgoingTransaction>>::iterator it = mOutgoings.begin(); it != mOutgoings.end();) {
			if (*it != transaction) {
				shared_ptr<OutgoingTransaction> tr = (*it);
				it = mOutgoings.erase(it);
				tr->cancel();
			} else {
				++it;
			}
		}
	}
}

void ForkCallContext::onRequest(const shared_ptr<IncomingTransaction> &transaction, shared_ptr<RequestSipEvent> &event) {
	event->setOutgoingAgent(shared_ptr<OutgoingAgent>());
	const shared_ptr<MsgSip> &ms = event->getMsgSip();
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_request != NULL) {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			LOGD("Fork: incomingCallback cancel");
			cancel();
			event->terminateProcessing();
		}
	}
}

static bool isARetryableResponseCode(int code){
	switch(code){
		case 401:
		case 407:
		case 415:
		case 420:
		case 484:
			return true;
		default:
			return false;
	}
	return false;
}

void ForkCallContext::store(shared_ptr<ResponseSipEvent> &event) {
	bool best = false;
	int code=event->getMsgSip()->getSip()->sip_status->st_status;

	//don't forward 503 and 408
	if (code!=503 && code!=408){
		if (mBestResponse != NULL) {
			//we must give priority to 401, 407, 415, 420, 484 because they will trigger a request retry.
			int prev_resp_code=mBestResponse->getMsgSip()->getSip()->sip_status->st_status;
			int code_class=code/100;
			int prev_code_class=prev_resp_code/100;
			
			if (code_class < prev_code_class) {
				best = true;
			}else if (isARetryableResponseCode(code)){
				best=true;
			}
		}else best=true;
	}
	// Save
	if (best) {
		mBestResponse = make_shared<ResponseSipEvent>(event); // Copy event
		mBestResponse->suspendProcessing();
	}

	// Don't forward
	event->setIncomingAgent(shared_ptr<IncomingAgent>());
}

void ForkCallContext::onResponse(const shared_ptr<OutgoingTransaction> &transaction, shared_ptr<ResponseSipEvent> &event) {
	event->setIncomingAgent(mIncoming);
	const shared_ptr<MsgSip> &ms = event->getMsgSip();
	sip_via_remove(ms->getMsg(), ms->getSip()); // remove via
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_status != NULL) {
		LOGD("Fork: outgoingCallback %d", sip->sip_status->st_status);
		if (sip->sip_status->st_status > 100 && sip->sip_status->st_status < 200) {
			forward(event);
			return;
		} else if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 300) {
			if (mCfg->mForkOneResponse) // TODO: respect RFC 3261 16.7.5
				cancelOthers(transaction);
			forward(event, true);
			return;
		} else if (sip->sip_status->st_status >= 600 && sip->sip_status->st_status < 700) {
			decline(transaction, event);
			return;
		} else {
			if (!mCancelled)
				store(event);
			else forward(event,true);
			return;
		}
	}

	LOGW("Outgoing transaction: ignore message");
}

void ForkCallContext::sendRinging(){
	// Create response
	if (mIncoming && mFinal==0){
		for (auto it = mForwardResponses.begin(); it!=mForwardResponses.end(); ++it){
			if (*it==180 || *it==183)
				return;
		}
		shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_180_RINGING));
		shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
		ev->setIncomingAgent(mIncoming);
		mAgent->sendResponseEvent(ev);
	}
}

void ForkCallContext::onNew(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

void ForkCallContext::onDestroy(const shared_ptr<IncomingTransaction> &transaction) {
	return ForkContext::onDestroy(transaction);
}

void ForkCallContext::onNew(const shared_ptr<OutgoingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

void ForkCallContext::checkFinished(){
	if (mOutgoings.size() == 0 && (mLateTimerExpired || mLateTimer==NULL)) {
		if (mIncoming != NULL && !hasFinalResponse()) {
			if (mBestResponse == NULL) {
				// Create response
				shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
				shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
				ev->setIncomingAgent(mIncoming);
				mAgent->sendResponseEvent(ev);
			} else {
				mAgent->injectResponseEvent(mBestResponse); // Reply
			}
			++mFinal;
		}
		mBestResponse.reset();
		setFinished();
	}
}

void ForkCallContext::onDestroy(const shared_ptr<OutgoingTransaction> &transaction) {
	
	ForkContext::onDestroy(transaction);
}

bool ForkCallContext::hasFinalResponse(){
	return mFinal>0 || mCancelled;
}
