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
#include <sofia-sip/su_tagarg.h>

using namespace ::std;

OutgoingTransaction::OutgoingTransaction(Agent *agent, const shared_ptr<OutgoingTransactionHandler> &handler) :
		Transaction(agent), outgoing(NULL), handler(handler) {
	LOGD("New OutgoingTransaction %p", this);

}

OutgoingTransaction::~OutgoingTransaction() {
	if (outgoing != NULL) {
		nta_outgoing_bind(outgoing, NULL, NULL); //avoid callbacks
		nta_outgoing_destroy(outgoing);
	}
	LOGD("Delete OutgoingTransaction %p", this);
}

void OutgoingTransaction::cancel() {
	nta_outgoing_cancel(outgoing);
}

void OutgoingTransaction::send(const shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	msg_ref_create(msg->getMsg());
	ta_list ta;
	ta_start(ta, tag, value);
	outgoing = nta_outgoing_mcreate(agent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, u, msg->getMsg(), ta_tags(ta));
	ta_end(ta);
	if (outgoing == NULL) {
		LOGE("Error during outgoing transaction creation");
		msg_destroy(msg->getMsg());
	} else {
		handler->onNew(this->shared_from_this());
	}
}

void OutgoingTransaction::send(const shared_ptr<MsgSip> &msg) {
	msg_ref_create(msg->getMsg());
	outgoing = nta_outgoing_mcreate(agent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, NULL, msg->getMsg(), TAG_END());
	if (outgoing == NULL) {
		LOGE("Error during outgoing transaction creation");
		msg_destroy(msg->getMsg());
	} else {
		handler->onNew(this->shared_from_this());
	}
}

void OutgoingTransaction::reply(const shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	LOGA("Can't reply on Outgoing transaction");
}

int OutgoingTransaction::_callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip) {
	OutgoingTransaction * it = reinterpret_cast<OutgoingTransaction *>(magic);
	if (it->handler != NULL) {
		if (sip != NULL) {
			msg_t *msg = nta_outgoing_getresponse(it->outgoing);
			shared_ptr<MsgSip> msgsip(new MsgSip(msg));
			msg_destroy(msg);
			it->handler->onEvent(it->shared_from_this(), make_shared<StatefulSipEvent>(it->shared_from_this(), msgsip));
			if (sip->sip_status && sip->sip_status->st_status >= 200) {
				it->handler->onDestroy(it->shared_from_this());
			}
		} else {
			it->handler->onDestroy(it->shared_from_this());
		}
	}
	return 0;
}

IncomingTransaction::IncomingTransaction(Agent *agent, const shared_ptr<IncomingTransactionHandler> &handler) :
		Transaction(agent), incoming(NULL), handler(handler) {
	LOGD("New IncomingTransaction %p", this);
}

void IncomingTransaction::handle(const std::shared_ptr<MsgSip> &ms) {
	msg_ref_create(ms->getMsg());
	incoming = nta_incoming_create(agent->mAgent, NULL, ms->getMsg(), ms->getSip(), TAG_END());
	if (incoming != NULL) {
		nta_incoming_bind(incoming, IncomingTransaction::_callback, (nta_incoming_magic_t*) this);
		handler->onNew(this->shared_from_this());
	} else {
		LOGE("Error during incoming transaction creation");
	}
}

IncomingTransaction::~IncomingTransaction() {
	if (incoming != NULL) {
		nta_incoming_bind(incoming, NULL, NULL); //avoid callbacks
		nta_incoming_destroy(incoming);
	}
	LOGD("Delete IncomingTransaction %p", this);
}

shared_ptr<MsgSip> IncomingTransaction::createResponse(int status, char const *phrase) {
	msg_t *msg = nta_incoming_create_response(incoming, status, phrase);
	shared_ptr<MsgSip> ms(make_shared<MsgSip>(msg));
	msg_destroy(msg);
	return ms;
}

void IncomingTransaction::send(const shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	msg_ref_create(msg->getMsg());
	nta_incoming_mreply(incoming, msg->getMsg());
}

void IncomingTransaction::send(const shared_ptr<MsgSip> &msg) {
	msg_ref_create(msg->getMsg());
	nta_incoming_mreply(incoming, msg->getMsg());
}

void IncomingTransaction::reply(const shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	nta_incoming_treply(incoming, status, phrase, ta_tags(ta));
	ta_end(ta);
}

int IncomingTransaction::_callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip) {
	IncomingTransaction * it = reinterpret_cast<IncomingTransaction *>(magic);
	if (it->handler != NULL) {
		if (sip != NULL) {
			msg_t *msg = nta_incoming_getrequest_ackcancel(it->incoming);
			shared_ptr<MsgSip> msgsip(new MsgSip(msg));
			msg_destroy(msg);
			it->handler->onEvent(it->shared_from_this(), make_shared<StatefulSipEvent>(it->shared_from_this(), msgsip));
			if (sip->sip_request && sip->sip_request->rq_method == sip_method_cancel) {
				it->handler->onDestroy(it->shared_from_this());
			}
		} else {
			it->handler->onDestroy(it->shared_from_this());
		}
	}
	return 0;
}
