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

ForkMessageContext::ForkMessageContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event) :
		ForkContext(agent, event), mFinal(0) {
	LOGD("New ForkMessageContext %p", this);
	GenericStruct *cr = GenericManager::get()->getRoot();
	GenericStruct *ma = cr->get<GenericStruct>("module::Registrar");
	mForkOneResponse = ma->get<ConfigBoolean>("fork-one-response")->read();
	mForkNoGlobalDecline = ma->get<ConfigBoolean>("fork-no-global-decline")->read();
}

ForkMessageContext::~ForkMessageContext() {
	LOGD("Destroy ForkMessageContext %p", this);
}

bool ForkMessageContext::hasFinalResponse(){
	return false;
}

void ForkMessageContext::cancel() {
	cancelOthers();
}

void ForkMessageContext::forward(const shared_ptr<SipEvent> &ev, bool force) {
	sip_t *sip = ev->getMsgSip()->getSip();
	bool fakeSipEvent = (mFinal > 0 && !force) || mIncoming == NULL;

	if (mForkOneResponse) { // TODO: respect RFC 3261 16.7.5
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

void ForkMessageContext::decline(const shared_ptr<OutgoingTransaction> &transaction, shared_ptr<ResponseSipEvent> &ev) {
	if (!mForkNoGlobalDecline) {
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

void ForkMessageContext::cancelOthers(const shared_ptr<OutgoingTransaction> &transaction) {
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

void ForkMessageContext::onRequest(const shared_ptr<IncomingTransaction> &transaction, shared_ptr<RequestSipEvent> &event) {
	event->setOutgoingAgent(shared_ptr<OutgoingAgent>());
	const shared_ptr<MsgSip> &ms = event->getMsgSip();
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_request != NULL) {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			LOGD("Fork: incomingCallback cancel");
			cancel();
		}
	}
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
		if (sip->sip_status->st_status > 100 && sip->sip_status->st_status < 200) {
			forward(event);
			return;
		} else if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 300) {
			if (mForkOneResponse) // TODO: respect RFC 3261 16.7.5
				cancelOthers(transaction);
			forward(event, true);
			return;
		} else if (sip->sip_status->st_status >= 600 && sip->sip_status->st_status < 700) {
			decline(transaction, event);
			return;
		} else {
			store(event);
			return;
		}
	}

	LOGW("Outgoing transaction: ignore message");
}

void ForkMessageContext::onNew(const shared_ptr<IncomingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

bool ForkMessageContext::onDestroy(const shared_ptr<IncomingTransaction> &transaction) {
	return ForkContext::onDestroy(transaction);
}

void ForkMessageContext::onNew(const shared_ptr<OutgoingTransaction> &transaction) {
	ForkContext::onNew(transaction);
}

bool ForkMessageContext::onDestroy(const shared_ptr<OutgoingTransaction> &transaction) {
	ForkContext::onDestroy(transaction);
	if (mOutgoings.size() == 0) {
		if (mIncoming != NULL && mFinal == 0) {
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
		mIncoming.reset();
	}
	return mIncoming == NULL && mOutgoings.size() == 0;
}
