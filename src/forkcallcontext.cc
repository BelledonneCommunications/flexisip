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
		mAgent(agent), mRinging(0), mEarlyMedia(0) {
	LOGD("New ForkCallContext %p", this);
}

ForkCallContext::~ForkCallContext() {
	LOGD("Destroy ForkCallContext %p", this);
}

void ForkCallContext::receiveOk(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	shared_ptr<MsgSip> ms = event->getMsgSip();
	shared_ptr<SipEvent> ev(new StatefulSipEvent(mIncoming, ms));
	mAgent->sendResponseEvent(ev);

	// Cancel others
	for (list<shared_ptr<OutgoingTransaction>>::iterator it = mOutgoings.begin(); it != mOutgoings.end(); ++it) {
		if (*it != transaction) {
			(*it)->cancel();
		}
	}
}

void ForkCallContext::receiveCancel(const std::shared_ptr<IncomingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	for (list<shared_ptr<OutgoingTransaction>>::iterator it = mOutgoings.begin(); it != mOutgoings.end(); ++it) {
		(*it)->cancel();
	}
	shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_487_REQUEST_CANCELLED));
	shared_ptr<SipEvent> ev(new StatefulSipEvent(mIncoming, msgsip));
	mAgent->sendResponseEvent(ev);
}

void ForkCallContext::receiveTimeout(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	/*
	 if (outgoings.size() == 0) {
	 msg_t *msg = nta_incoming_create_response(incoming->getIncoming(), SIP_408_REQUEST_TIMEOUT);
	 shared_ptr<MsgSip> msgsip(new MsgSip(msg, sip_object(msg)));
	 msg_ref_destroy(msg);
	 shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msgsip));
	 agent->sendResponseEvent(ev);
	 deleteTransaction(incoming);
	 }
	 */
}

void ForkCallContext::receiveDecline(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	/*	if (outgoings.size() == 0) {
	 msg_t *msg = nta_incoming_create_response(incoming->getIncoming(), SIP_603_DECLINE);
	 shared_ptr<MsgSip> msgsip(new MsgSip(msg, sip_object(msg)));
	 msg_ref_destroy(msg);
	 shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msgsip));
	 agent->sendResponseEvent(ev);
	 deleteTransaction(incoming);
	 }
	 */
}

void ForkCallContext::receiveEarlyMedia(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	if (mIncoming.get()) {
		shared_ptr<SipEvent> ev;
		if (mRinging)
			ev = make_shared<NullSipEvent>(event->getMsgSip());
		else
			ev = make_shared<StatefulSipEvent>(mIncoming, event->getMsgSip());
		++mRinging;
		mAgent->sendResponseEvent(ev);
	}

}

void ForkCallContext::receiveCanceled(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	shared_ptr<SipEvent> ev = make_shared<NullSipEvent>(event->getMsgSip());
	mAgent->sendResponseEvent(ev);
}

void ForkCallContext::receiveRinging(const std::shared_ptr<OutgoingTransaction> &transaction, const std::shared_ptr<StatefulSipEvent> &event) {
	if (mIncoming.get()) {
		shared_ptr<SipEvent> ev;
		if (mEarlyMedia)
			ev = make_shared<NullSipEvent>(event->getMsgSip());
		else
			ev = make_shared<StatefulSipEvent>(mIncoming, event->getMsgSip());
		++mEarlyMedia;
		mAgent->sendResponseEvent(ev);
	}

}

void ForkCallContext::onEvent(const shared_ptr<IncomingTransaction> &transaction, const shared_ptr<StatefulSipEvent> &event) {
	shared_ptr<MsgSip> ms = event->getMsgSip();
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_request != NULL) {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			LOGD("Fork: incomingCallback cancel");
			receiveCancel(transaction, event);
			return;
		}
	}
	LOGW("Incoming transaction: ignore message");
}

void ForkCallContext::onEvent(const shared_ptr<OutgoingTransaction> &transaction, const shared_ptr<StatefulSipEvent> &event) {
	shared_ptr<MsgSip> ms = event->getMsgSip();
	sip_via_remove(ms->getMsg(), ms->getSip()); // remove via @see test_proxy.c from sofia
	sip_t *sip = ms->getSip();
	if (sip != NULL && sip->sip_status != NULL) {
		LOGD("Fork: outgoingCallback %d", sip->sip_status->st_status);
		if (sip->sip_status->st_status == 200) {
			receiveOk(transaction, event);
			return;
		} else if (sip->sip_status->st_status == 408 || sip->sip_status->st_status == 503) {
			receiveTimeout(transaction, event);
			return;
		} else if (sip->sip_status->st_status == 603) {
			receiveDecline(transaction, event);
			return;
		} else if (sip->sip_status->st_status == 180) {
			receiveRinging(transaction, event);
			return;
		} else if (sip->sip_status->st_status == 183) {
			receiveEarlyMedia(transaction, event);
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
}
