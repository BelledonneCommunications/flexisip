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
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>

using namespace ::std;

ForkMessageContext::ForkMessageContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		ForkContext(agent, event,cfg,listener), mDelivered(false) {
	LOGD("New ForkMessageContext %p", this);
}

ForkMessageContext::~ForkMessageContext() {
	LOGD("Destroy ForkMessageContext %p", this);
}

bool ForkMessageContext::hasFinalResponse(){
	return mDelivered;
}


void ForkMessageContext::forward(const shared_ptr<SipEvent> &ev) {
	sip_t *sip = ev->getMsgSip()->getSip();
	
	if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 700) {
		mDelivered=true;
		mListener->onForkContextFinished(shared_from_this());
	}
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

void ForkMessageContext::onNew(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

void ForkMessageContext::onDestroy(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onDestroy(transaction);
}

void ForkMessageContext::onNew(const shared_ptr<OutgoingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

void ForkMessageContext::onDestroy(const shared_ptr<OutgoingTransaction> &transaction) {
	if (mOutgoings.size() == 1) {
		if (mIncoming != NULL && !mDelivered) {
			if (mBestResponse == NULL && mCfg->mDeliveryTimeout < 25) {
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
		mBestResponse.reset();
		mIncoming.reset();
	}
	ForkContext::onDestroy(transaction);
}
