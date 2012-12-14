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

#include "forkmessagecontext.hh"
#include "registrardb.hh"
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>

using namespace ::std;

ForkMessageContext::ForkMessageContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		ForkContext(agent, event,cfg,listener), mDeliveredCount(0) {
	LOGD("New ForkMessageContext %p", this);
	mAcceptanceTimer=NULL;
}

ForkMessageContext::~ForkMessageContext() {
	if (mAcceptanceTimer)
		su_timer_destroy(mAcceptanceTimer);
	LOGD("Destroy ForkMessageContext %p", this);
}

void ForkMessageContext::markAsDelivered(const shared_ptr<SipEvent> &ev){
	shared_ptr<OutgoingTransaction> tr=dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	shared_ptr<string> uid=tr->getProperty<string>("contact-unique-id");
	if (uid!=NULL && uid->size()>0){
		LOGD("ForkMessageContext: Marking %s as delivered",uid->c_str());
		mDeliveryMap[*uid]=true;
	}
}

void ForkMessageContext::forward(const shared_ptr<SipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();
	
	if (sip->sip_status->st_status >= 200 ) {
		markAsDelivered(ev);
		mDeliveredCount++;
		if (mDeliveredCount>1){
			/*should only transfer one response*/
			ev->setIncomingAgent(shared_ptr<IncomingAgent>());
		}
		checkFinished();
	}
}

void ForkMessageContext::checkFinished(){
	bool everyone_delivered=true;
	for (auto it=mDeliveryMap.begin();it!=mDeliveryMap.end();++it){
		if ((*it).second==false) everyone_delivered=false;
	}
	if (mDeliveryMap.size()>0 && everyone_delivered){
		LOGD("ForkMessageContext::checkFinished(): every instance received the message, it's finished.");
		setFinished();
		return;
	}
	/*otherwise, we wait the expiry of the ForkContext late timer*/
	return ForkContext::checkFinished();
}

void ForkMessageContext::onRequest(const shared_ptr<IncomingTransaction> &transaction, shared_ptr<RequestSipEvent> &event) {
	
}

void ForkMessageContext::store(shared_ptr<ResponseSipEvent> &event) {
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

void ForkMessageContext::onResponse(const shared_ptr<OutgoingTransaction> &transaction, shared_ptr<ResponseSipEvent> &event) {
	event->setIncomingAgent(mIncoming);
	const shared_ptr<MsgSip> &ms = event->getMsgSip();
	sip_via_remove(ms->getMsg(), ms->getSip()); // remove via
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_status != NULL) {
		LOGD("Fork: outgoingCallback %d", sip->sip_status->st_status);
		if (sip->sip_status->st_status > 100 && sip->sip_status->st_status < 300) {
			forward(event);
			return;
		} else {
			store(event);
			return;
		}
	}
	LOGW("ForkMessageContext : ignore message");
}

void ForkMessageContext::finishIncomingTransaction(){
	if (mIncoming != NULL && mDeliveredCount==0) {
		if (mBestResponse == NULL && mCfg->mDeliveryTimeout <= 30) {
			// Create response
			shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
			shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
			ev->setIncomingAgent(mIncoming);
			mAgent->sendResponseEvent(ev);
		} else {
			int code=mBestResponse ? mBestResponse->getMsgSip()->getSip()->sip_status->st_status : 0;
			if (!mBestResponse || code==408 || code==503){
				if (mCfg->mForkLate){
					/*in fork late mode, never answer a service unavailable*/
					shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_202_ACCEPTED));
					shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
					ev->setIncomingAgent(mIncoming);
					mAgent->sendResponseEvent(ev);
				}
			}else 
				mAgent->injectResponseEvent(mBestResponse); // Reply
		}
	}
	if (mAcceptanceTimer){
		su_timer_destroy(mAcceptanceTimer);
		mAcceptanceTimer=NULL;
	}
	mBestResponse.reset();
	mIncoming.reset();
}

void ForkMessageContext::onAcceptanceTimer(){
	LOGD("ForkMessageContext::onAcceptanceTimer()");
	finishIncomingTransaction();
}

void ForkMessageContext::sOnAcceptanceTimer(su_root_magic_t* magic, su_timer_t* t, su_timer_arg_t* arg){
	static_cast<ForkMessageContext*>(arg)->onAcceptanceTimer();
}


void ForkMessageContext::onNew(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onNew(transaction);
	//start the acceptance timer immediately
	if (mCfg->mForkLate && mCfg->mDeliveryTimeout>30){
		mAcceptanceTimer=su_timer_create(su_root_task(mAgent->getRoot()), 0);
		su_timer_set_interval(mAcceptanceTimer, &ForkMessageContext::sOnAcceptanceTimer, this, (su_duration_t)20000);
	}
}

void ForkMessageContext::onDestroy(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onDestroy(transaction);
}

void ForkMessageContext::onNew(const shared_ptr<OutgoingTransaction> &transaction) {
	const url_t *dest=transaction->getRequestUri();
	string uid=Record::extractUniqueId(dest);
	if (uid.size()>0){
		auto it=mDeliveryMap.find(uid);
		if (it==mDeliveryMap.end()){
			LOGD("ForkMessageContext: adding %s as potential receiver of message.",uid.c_str());
			mDeliveryMap[uid]=false;
		}
		transaction->setProperty<string>("contact-unique-id",make_shared<string>(uid));
	}
	ForkContext::onNew(transaction);
}

void ForkMessageContext::onDestroy(const shared_ptr<OutgoingTransaction> &transaction) {
	if (mOutgoings.size() == 1) {
		finishIncomingTransaction();
	}
	ForkContext::onDestroy(transaction);
}

bool ForkMessageContext::onNewRegister(const sip_contact_t *ctt){
	bool already_have_transaction=!ForkContext::onNewRegister(ctt);
	if (already_have_transaction) return false;
	string unique_id=Record::extractUniqueId(ctt);
	if (unique_id.size()>0){
		auto it=mDeliveryMap.find(unique_id);
		if (it==mDeliveryMap.end()){
			//this is a new client instance or a client for which the message wasn't delivered yet. The message needs to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this is a new client instance.");
			return true;
		}else if ((*it).second==false){
			//this is a new client instance or a client for which the message wasn't delivered yet. The message needs to be delivered.
			LOGD("ForkMessageContext::onNewRegister(): this client is reconnecting but was not delivered before.");
			return true;
		}
	}
	//in all other case we can accept a new transaction only if the message hasn't been delivered already.
	LOGD("Message has been delivered %i times.",mDeliveredCount);
	return mDeliveredCount==0;
}

