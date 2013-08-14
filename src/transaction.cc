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
	LOGD("Delete OutgoingTransaction %p", this);
}

void OutgoingTransaction::cancel() {
	nta_outgoing_cancel(mOutgoing);
	// Maybe it is not a good idea to destroy the sofia transaction immediately after cancelling it.
	//Indeed, sofia keeps the transaction open in case no provisional response has been received so far, so that the Cancel is sent
	//after receiving the response, as requested by the RFC.
	//Destroying the transaction here is suspected to generate rare crashes like the backtrace below, when a 200Ok for invite response is received, 
	//for a cancelled transaction.
/*
#1  0x00007f796113dfc0 in *__GI_abort () at abort.c:92
#2  0x00007f7961134301 in *__GI___assert_fail (
    assertion=0x7f7963dfbb88 "orq->orq_queue == sa->sa_out.completed || orq->orq_queue == sa->sa_out.terminated", file=<value optimized out>, 
    line=9298, function=0x7f7963dfc863 "outgoing_recv") at assert.c:81
#3  0x00007f7963d6023e in ?? () from /usr/lib/libsofia-sip-ua.so.0
#4  0x00007f7963d6c04c in ?? () from /usr/lib/libsofia-sip-ua.so.0
#5  0x00007f7963ddbee5 in tport_deliver () from /usr/lib/libsofia-sip-ua.so.0
*/
	
	destroy();
}

const url_t *OutgoingTransaction::getRequestUri()const{
	if (mOutgoing==NULL){
		LOGE("OutgoingTransaction::getRequestUri(): transaction not started !");
		return NULL;
	}
	return nta_outgoing_request_uri(mOutgoing);
}

void OutgoingTransaction::send(const shared_ptr<MsgSip> &ms, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	msg_t* msg = msg_dup(ms->getMsg());
	ta_list ta;
	ta_start(ta, tag, value);
	LOGD("Message is sent through an outgoing transaction.");
	mOutgoing = nta_outgoing_mcreate(mAgent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, u, msg, ta_tags(ta));
	ta_end(ta);
	if (mOutgoing == NULL) {
		LOGE("Error during outgoing transaction creation");
		msg_destroy(msg);
	} else {
		mSofiaRef = shared_from_this();
		mAgent->sendTransactionEvent(TransactionEvent::makeCreate(shared_from_this()));
	}
	
}

void OutgoingTransaction::send(const shared_ptr<MsgSip> &ms) {
	msg_t* msg = msg_dup(ms->getMsg());
	LOGD("Message is sent through an outgoing transaction.");
	mOutgoing = nta_outgoing_mcreate(mAgent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, NULL, msg, TAG_END());
	if (mOutgoing == NULL) {
		LOGE("Error during outgoing transaction creation");
		msg_destroy(msg);
	} else {
		mSofiaRef = shared_from_this();
		mAgent->sendTransactionEvent(TransactionEvent::makeCreate(shared_from_this()));
	}
	
}

int OutgoingTransaction::_callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip) {
	OutgoingTransaction * otr = reinterpret_cast<OutgoingTransaction *>(magic);
	LOGD("OutgoingTransaction callback %p", otr);
	if (sip != NULL) {
		msg_t *msg = nta_outgoing_getresponse(otr->mOutgoing);
		auto oagent=dynamic_pointer_cast<OutgoingAgent>(otr->shared_from_this());
		auto msgsip=shared_ptr<MsgSip>(new MsgSip(msg));
		shared_ptr<ResponseSipEvent> sipevent(new ResponseSipEvent(oagent, msgsip));
		msg_destroy(msg);

		otr->mAgent->sendResponseEvent(sipevent);
		if (sip->sip_status && sip->sip_status->st_status >= 200) {
			otr->destroy();
		}
	} else {
		otr->destroy();
	}
	return 0;
}

void OutgoingTransaction::destroy() {
	if (mSofiaRef != NULL) {
		mSofiaRef.reset();
		mAgent->sendTransactionEvent(TransactionEvent::makeDestroy(shared_from_this()));
		nta_outgoing_bind(mOutgoing, NULL, NULL); //avoid callbacks
		nta_outgoing_destroy(mOutgoing);
		mIncoming.reset();
		looseProperties();
	}
}

IncomingTransaction::IncomingTransaction(Agent *agent) :
		Transaction(agent), mIncoming(NULL) {
	LOGD("New IncomingTransaction %p", this);
}

void IncomingTransaction::handle(const shared_ptr<MsgSip> &ms) {
	msg_t* msg = ms->mOriginalMsg;
	msg_ref_create(msg);
	mIncoming = nta_incoming_create(mAgent->mAgent, NULL, msg, sip_object(msg), TAG_END());
	if (mIncoming != NULL) {
		nta_incoming_bind(mIncoming, IncomingTransaction::_callback, (nta_incoming_magic_t*) this);
		mSofiaRef = shared_from_this();

		mAgent->sendTransactionEvent(TransactionEvent::makeCreate(shared_from_this()));
	} else {
		LOGE("Error during incoming transaction creation");
	}
}

IncomingTransaction::~IncomingTransaction() {
	LOGD("Delete IncomingTransaction %p", this);
}

shared_ptr<MsgSip> IncomingTransaction::createResponse(int status, char const *phrase) {
	msg_t *msg = nta_incoming_create_response(mIncoming, status, phrase);
	shared_ptr<MsgSip> ms(shared_ptr<MsgSip>(new MsgSip(msg)));
	msg_destroy(msg);
	return ms;
}

void IncomingTransaction::send(const shared_ptr<MsgSip> &ms, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	if (mIncoming) {
		msg_t* msg = msg_dup(ms->getMsg()); //need to duplicate the message because mreply will decrement its ref count.
		LOGD("Response is sent through an incoming transaction.");
		nta_incoming_mreply(mIncoming, msg);
		if (ms->getSip()->sip_status != NULL && ms->getSip()->sip_status->st_status >= 200) {
			destroy();
		}
	} else {
		LOGW("Invalid incoming");
	}
}

void IncomingTransaction::send(const shared_ptr<MsgSip> &ms) {
	if (mIncoming) {
		msg_t* msg = msg_dup(ms->getMsg());
		LOGD("Response is sent through an incoming transaction.");
		nta_incoming_mreply(mIncoming, msg);
		if (ms->getSip()->sip_status != NULL && ms->getSip()->sip_status->st_status >= 200) {
			destroy();
		}
	} else {
		LOGW("Invalid incoming");
	}
}

void IncomingTransaction::reply(const shared_ptr<MsgSip> &msgIgnored, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	if (mIncoming) {
		mAgent->incrReplyStat(status);
		ta_list ta;
		ta_start(ta, tag, value);
		nta_incoming_treply(mIncoming, status, phrase, ta_tags(ta));
		ta_end(ta);
		if (status >= 200) {
			destroy();
		}
	} else {
		LOGW("Invalid incoming");
	}
}

int IncomingTransaction::_callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip) {
	IncomingTransaction * it = reinterpret_cast<IncomingTransaction *>(magic);
	LOGD("IncomingTransaction callback %p", it);
	if (sip != NULL) {
		msg_t *msg = nta_incoming_getrequest_ackcancel(it->mIncoming);
		auto ev = make_shared<RequestSipEvent>(it->shared_from_this(),
				MsgSip::createFromOriginalMsg(msg),
				shared_ptr<tport_t>() /* no access to nta_agent: may put tport in transaction if needed  */
		);
		msg_destroy(msg);
		it->mAgent->sendRequestEvent(ev);
		if (sip->sip_request && sip->sip_request->rq_method == sip_method_cancel) {
			it->destroy();
		}
	} else {
		it->destroy();
	}
	return 0;
}

void IncomingTransaction::destroy() {
	if (mSofiaRef != NULL) {
		mSofiaRef.reset();
		mAgent->sendTransactionEvent(TransactionEvent::makeDestroy(shared_from_this()));
		nta_incoming_bind(mIncoming, NULL, NULL); //avoid callbacks
		nta_incoming_destroy(mIncoming);
		looseProperties();
	}
}
