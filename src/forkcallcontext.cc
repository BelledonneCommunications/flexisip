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
		ForkContext(agent, event,cfg, listener), mShortTimer(NULL), mFinal(0), mCancelled(false) {
	LOGD("New ForkCallContext %p", this);
	mLog=event->getEventLog<CallLog>();
}

ForkCallContext::~ForkCallContext() {
	LOGD("Destroy ForkCallContext %p", this);
	if (mShortTimer){
		su_timer_destroy(mShortTimer);
		mShortTimer=NULL;
	}
}

void ForkCallContext::cancel() {
	mLog->setCancelled();
	mLog->setCompleted();
	mCancelled=true;
	cancelOthers();
}

void ForkCallContext::forward(const shared_ptr<ResponseSipEvent> &ev, bool force) {
	sip_t *sip = ev->getMsgSip()->getSip();
	bool fakeSipEvent = (mFinal > 0 && !force) || mIncoming == NULL;
	const int status = sip->sip_status->st_status;

	if (mCfg->mForkOneResponse) { // TODO: respect RFC 3261 16.7.5
		if (status == 183 || status == 180 || status == 101) {
			auto it = find(mForwardResponses.begin(), mForwardResponses.end(), status);
			if (it != mForwardResponses.end()) {
				fakeSipEvent = true;
			} else {
				mForwardResponses.push_back(status);
			}
		}
	}

	if (fakeSipEvent) {
		ev->setIncomingAgent(shared_ptr<IncomingAgent>());
	}else{
		if (mCfg->mRemoveToTag && (status == 183 || status == 180 || status == 101)) {
			SLOGD << "Removing 'to tag' ";
			msg_header_remove_param((msg_common_t *)sip->sip_to, "tag");
		}
		logResponse(ev);
	}

	if (status >= 200 && status < 700) {
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

bool ForkCallContext::isRetryableOrUrgent(int code){
	switch(code){
		case 401:
		case 407:
		case 415:
		case 420:
		case 484:
			return true;
		case 603:
			if (mCfg->mTreatDeclineAsUrgent)
				return true;
		default:
			return false;
	}
	return false;
}

void ForkCallContext::store(shared_ptr<ResponseSipEvent> &event) {
	bool best = false;
	int code=event->getMsgSip()->getSip()->sip_status->st_status;

	if (mBestResponse != NULL) {
		//we must give priority to 401, 407, 415, 420, 484 because they will trigger a request retry.
		int prev_resp_code=mBestResponse->getMsgSip()->getSip()->sip_status->st_status;
		int code_class=code/100;
		int prev_code_class=prev_resp_code/100;
		
		if (code_class < prev_code_class) {
			best = true;
		}else if (isRetryableOrUrgent(code)){
			if (mShortTimer==NULL){
				mShortTimer=su_timer_create(su_root_task(mAgent->getRoot()), 0);
				su_timer_set_interval(mShortTimer, &ForkCallContext::sOnShortTimer, this, (su_duration_t)mCfg->mUrgentTimeout*1000);
			}
			best=true;
		}
	}else best=true;
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
		int code=sip->sip_status->st_status;
		LOGD("Fork: outgoingCallback %d", sip->sip_status->st_status);
		if (code > 100 && code < 200) {
			forward(event);
			return;
		} else if (code >= 200 && code < 300) {
			if (mCfg->mForkOneResponse) // TODO: respect RFC 3261 16.7.5
				cancelOthers(transaction);
			forward(event, true);
			return;
		} else if (code >= 600 && code < 700) {
			decline(transaction, event);
			return;
		} else {
			//ignore  503 and 408
			if (code!=503 && code!=408){
				if (mOutgoings.size()<2){
					//optimization: when there is a single branch in the fork, send all the response immediately.
					forward(event,true);
					
				}else if (!mCancelled){
					store(event);
				}else{
					forward(event,true);
				}
				return;
			}else{// Don't forward
				event->setIncomingAgent(shared_ptr<IncomingAgent>());
			}
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
		//add a to tag, no set by sofia here.
		if (!mCfg->mRemoveToTag) {
			const char *totag=nta_agent_newtag(msgsip->getHome(),"%s",mAgent->getSofiaAgent());
			sip_to_tag(msgsip->getHome(), msgsip->getSip()->sip_to, totag);
		}
		ev->setIncomingAgent(mIncoming);
		sendResponse(ev,false);
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

void ForkCallContext::logResponse(const shared_ptr<ResponseSipEvent> &ev){
	sip_t *sip=ev->getMsgSip()->getSip();
	mLog->setStatusCode(sip->sip_status->st_status,sip->sip_status->st_phrase);
	if (sip->sip_status->st_status>=200)
		mLog->setCompleted();
	ev->setEventLog(mLog);
}

void ForkCallContext::sendResponse(shared_ptr<ResponseSipEvent> ev, bool inject){
	logResponse(ev);
	if (inject)
		mAgent->injectResponseEvent(ev);
	else 
		mAgent->sendResponseEvent(ev);
}

void ForkCallContext::checkFinished(){
	if (mOutgoings.size() == 0 && ((mLateTimerExpired || mLateTimer==NULL) || mIncoming==NULL)) {
		if (mIncoming != NULL && !isCompleted()) {
			if (mBestResponse == NULL) {
				// Create response
				shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
				shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
				ev->setIncomingAgent(mIncoming);
				sendResponse(ev,false);
			} else {
				sendResponse(mBestResponse,true);
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


bool ForkCallContext::onNewRegister(const sip_contact_t *ctt){
	if (isCompleted()) return false;
	return ForkContext::onNewRegister(ctt);
}

bool ForkCallContext::isCompleted()const{
	return mFinal>0 || mCancelled || mIncoming==NULL;
}

void ForkCallContext::onShortTimer(){
	if (!isCompleted() && isRetryableOrUrgent(mBestResponse->getMsgSip()->getSip()->sip_status->st_status)){
		cancelOthers(static_pointer_cast<OutgoingTransaction>(mBestResponse->getOutgoingAgent()));
		sendResponse(mBestResponse,true);// send urgent reply immediately
		mBestResponse.reset();
	}
	su_timer_destroy(mShortTimer);
	mShortTimer=NULL;
}

void ForkCallContext::sOnShortTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg){
	ForkCallContext *zis=static_cast<ForkCallContext*>(arg);
	zis->onShortTimer();
}

