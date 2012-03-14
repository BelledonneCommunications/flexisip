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

ForkCallContext::ForkCallContext(Agent *agent) :
		mAgent(agent), mFinal(0) {
	LOGD("New ForkCallContext %p", this);
	ConfigStruct *cr = ConfigManager::get()->getRoot();
	ConfigStruct *ma = cr->get<ConfigStruct>("module::Registrar");
	mForkOneResponse = ma->get<ConfigBoolean>("fork-one-response")->read();
}

ForkCallContext::~ForkCallContext() {
	LOGD("Destroy ForkCallContext %p", this);
}

void ForkCallContext::cancel() {
	for (list<shared_ptr<OutgoingTransaction>>::iterator it = mOutgoings.begin(); it != mOutgoings.end(); ++it) {
		(*it)->cancel();
	}

	forward(mIncoming->createResponse(SIP_487_REQUEST_CANCELLED));
}

void ForkCallContext::forward(const std::shared_ptr<MsgSip> &ms, bool force) {
	sip_t *sip = ms->getSip();
	shared_ptr<SipEvent> ev;
	bool fakeSipEvent = (mFinal > 0 && !force) || mIncoming.get() == NULL;

	if(mForkOneResponse) { // TODO: respect RFC 3261 16.7.5
		if(sip->sip_status->st_status == 183 || sip->sip_status->st_status == 180) {
			auto it = find(mForwardResponses.begin(), mForwardResponses.end(), sip->sip_status->st_status);
			if(it != mForwardResponses.end()) {
				fakeSipEvent = true;
			} else {
				mForwardResponses.push_back(sip->sip_status->st_status);
			}
		}
	}

	if (fakeSipEvent) {
		ev = make_shared<NullSipEvent>(ms);
	} else {
		ev = make_shared<StatefulSipEvent>(mIncoming, ms);
	}

	mAgent->sendResponseEvent(ev);

	if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 700) {
		++mFinal;
	}
}

void ForkCallContext::decline(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<MsgSip> &ms) {
	closeOthers(transaction);

	forward(ms);
}

void ForkCallContext::closeOthers(const shared_ptr<OutgoingTransaction> &transaction) {
	if (mFinal == 0) {
		for (list<shared_ptr<OutgoingTransaction>>::iterator it = mOutgoings.begin(); it != mOutgoings.end(); ++it) {
			if (*it != transaction)
				(*it)->cancel();
		}
	}
}

void ForkCallContext::onEvent(const shared_ptr<IncomingTransaction> &transaction, const shared_ptr<StatefulSipEvent> &event) {
	shared_ptr<MsgSip> ms = event->getMsgSip();
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_request != NULL) {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			LOGD("Fork: incomingCallback cancel");
			cancel();
			return;
		}
	}
	LOGW("Incoming transaction: ignore message");
}

void ForkCallContext::store(const std::shared_ptr<MsgSip> &ms) {
	bool best = true;

	if (mBestResponse.get() != NULL) {
		if (mBestResponse->getSip()->sip_status->st_status < ms->getSip()->sip_status->st_status) {
			best = false;
		}
	}

	if (best) {
		if (mBestResponse.get() != NULL) {
			shared_ptr<SipEvent> ev = make_shared<NullSipEvent>(mBestResponse);
			mAgent->sendResponseEvent(ev);
		}
		mBestResponse = ms;
	} else {
		shared_ptr<SipEvent> ev = make_shared<NullSipEvent>(ms);
		mAgent->sendResponseEvent(ev);
	}
}

void ForkCallContext::onEvent(const shared_ptr<OutgoingTransaction> &transaction, const shared_ptr<StatefulSipEvent> &event) {
	shared_ptr<MsgSip> ms = event->getMsgSip();
	sip_via_remove(ms->getMsg(), ms->getSip()); // remove via
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_status != NULL) {
		LOGD("Fork: outgoingCallback %d", sip->sip_status->st_status);
		if (sip->sip_status->st_status > 100 && sip->sip_status->st_status < 200) {
			forward(event->getMsgSip());
			return;
		} else if (sip->sip_status->st_status >= 200 && sip->sip_status->st_status < 300) {
			if (mFinal == 0 && mForkOneResponse) // TODO: respect RFC 3261 16.7.5
				closeOthers(transaction);
			forward(event->getMsgSip(), true);
			return;
		} else if (sip->sip_status->st_status >= 600 && sip->sip_status->st_status < 700) {
			decline(transaction, event->getMsgSip());
			return;
		} else {
			store(event->getMsgSip());
			return;
		}
	}

	LOGW("Outgoing transaction: ignore message");
}

void ForkCallContext::onNew(const std::shared_ptr<IncomingTransaction> &transaction) {
	mIncoming = transaction;
}

void ForkCallContext::onDestroy(const std::shared_ptr<IncomingTransaction> &transaction) {
	mIncoming.reset();
}

void ForkCallContext::onNew(const std::shared_ptr<OutgoingTransaction> &transaction) {
	mOutgoings.push_back(transaction);
}

void ForkCallContext::onDestroy(const std::shared_ptr<OutgoingTransaction> &transaction) {
	mOutgoings.remove(transaction);
	if (mOutgoings.size() == 0) {
		if (mIncoming.get() != NULL) {
			if (mBestResponse.get() == NULL) {
				shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
				shared_ptr<SipEvent> ev(new StatefulSipEvent(mIncoming, msgsip));
				mAgent->sendResponseEvent(ev);
			} else {
				shared_ptr<SipEvent> ev(new StatefulSipEvent(mIncoming, mBestResponse));
				mAgent->sendResponseEvent(ev);
			}
			++mFinal;
		}
		mIncoming.reset();
	}
}
