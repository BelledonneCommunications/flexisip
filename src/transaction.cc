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

#include "transaction.hh"
#include "event.hh"
#include "common.hh"
#include "agent.hh"
#include <algorithm>
#include <sofia-sip/su_tagarg.h>

using namespace ::std;

OutgoingTransaction::OutgoingTransaction(Agent *agent) :
		Transaction(agent), mOutgoing(NULL) {
	LOGD("New OutgoingTransaction %p", this);

}

OutgoingTransaction::~OutgoingTransaction() {
	if (mOutgoing != NULL) {
		nta_outgoing_bind(mOutgoing, NULL, NULL); //avoid callbacks
		nta_outgoing_destroy(mOutgoing);
	}
	LOGD("Delete OutgoingTransaction %p", this);
}

void OutgoingTransaction::cancel() {
	nta_outgoing_cancel(mOutgoing);
}

void OutgoingTransaction::send(const shared_ptr<MsgSip> &ms, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	msg_t* msg = msg_dup(ms->getMsg());
	ta_list ta;
	ta_start(ta, tag, value);
	mOutgoing = nta_outgoing_mcreate(mAgent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, u, msg, ta_tags(ta));
	ta_end(ta);
	if (mOutgoing == NULL) {
		LOGE("Error during outgoing transaction creation");
		msg_destroy(msg);
	} else {
		mSofiaRef = shared_from_this();
		mAgent->sendTransactionEvent(shared_from_this(), Transaction::Create);
	}
}

void OutgoingTransaction::send(const shared_ptr<MsgSip> &ms) {
	msg_t* msg = msg_dup(ms->getMsg());
	mOutgoing = nta_outgoing_mcreate(mAgent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, NULL, msg, TAG_END());
	if (mOutgoing == NULL) {
		LOGE("Error during outgoing transaction creation");
		msg_destroy(msg);
	} else {
		mSofiaRef = shared_from_this();
		mAgent->sendTransactionEvent(shared_from_this(), Transaction::Create);
	}
}

int OutgoingTransaction::_callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip) {
	OutgoingTransaction * it = reinterpret_cast<OutgoingTransaction *>(magic);
	if (sip != NULL) {
		msg_t *msg = nta_outgoing_getresponse(it->mOutgoing);
		shared_ptr<SipEvent> sipevent(new ResponseSipEvent(it->shared_from_this(), make_shared<MsgSip>(msg)));
		msg_destroy(msg);
		it->mAgent->sendResponseEvent(sipevent);
		if (sip->sip_status && sip->sip_status->st_status >= 200) {
			it->destroy();
		}
	} else {
		it->destroy();
	}
	return 0;
}

void OutgoingTransaction::destroy() {
	mAgent->sendTransactionEvent(shared_from_this(), Transaction::Destroy);
	mSofiaRef.reset();
}

IncomingTransaction::IncomingTransaction(Agent *agent) :
		Transaction(agent), mIncoming(NULL) {
	LOGD("New IncomingTransaction %p", this);
}

void IncomingTransaction::handle(const std::shared_ptr<MsgSip> &ms) {
	msg_t* msg = msg_dup(ms->getMsg());
	mIncoming = nta_incoming_create(mAgent->mAgent, NULL, msg, sip_object(msg), TAG_END());
	if (mIncoming != NULL) {
		nta_incoming_bind(mIncoming, IncomingTransaction::_callback, (nta_incoming_magic_t*) this);
		mSofiaRef = shared_from_this();
	} else {
		LOGE("Error during incoming transaction creation");
	}
}

IncomingTransaction::~IncomingTransaction() {
	if (mIncoming != NULL) {
		nta_incoming_bind(mIncoming, NULL, NULL); //avoid callbacks
		nta_incoming_destroy(mIncoming);
	}
	LOGD("Delete IncomingTransaction %p", this);
}

shared_ptr<MsgSip> IncomingTransaction::createResponse(int status, char const *phrase) {
	msg_t *msg = nta_incoming_create_response(mIncoming, status, phrase);
	shared_ptr<MsgSip> ms(make_shared<MsgSip>(msg));
	msg_destroy(msg);
	return ms;
}

void IncomingTransaction::send(const shared_ptr<MsgSip> &ms, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	msg_t* msg = msg_dup(ms->getMsg());
	nta_incoming_mreply(mIncoming, msg);
	if (ms->getSip()->sip_status != NULL && ms->getSip()->sip_status->st_status >= 200) {
		destroy();
	}
}

void IncomingTransaction::send(const shared_ptr<MsgSip> &ms) {
	msg_t* msg = msg_dup(ms->getMsg());
	nta_incoming_mreply(mIncoming, msg);
	if (ms->getSip()->sip_status != NULL && ms->getSip()->sip_status->st_status >= 200) {
		destroy();
	}
}

void IncomingTransaction::reply(const shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	nta_incoming_treply(mIncoming, status, phrase, ta_tags(ta));
	ta_end(ta);
	if (status >= 200) {
		destroy();
	}
}

int IncomingTransaction::_callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip) {
	IncomingTransaction * it = reinterpret_cast<IncomingTransaction *>(magic);
	if (sip != NULL) {
		msg_t *msg = nta_incoming_getrequest_ackcancel(it->mIncoming);
		shared_ptr<SipEvent> sipevent(new RequestSipEvent(it->shared_from_this(), make_shared<MsgSip>(msg)));
		msg_destroy(msg);
		it->mAgent->sendRequestEvent(sipevent);
		if (sip->sip_request && sip->sip_request->rq_method == sip_method_cancel) {
			it->destroy();
		}
	} else {
		it->destroy();
	}
	return 0;
}

void IncomingTransaction::destroy() {
	mAgent->sendTransactionEvent(shared_from_this(), Transaction::Destroy);
	mSofiaRef.reset();
}
