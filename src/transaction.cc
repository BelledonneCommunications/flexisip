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

OutgoingTransaction::OutgoingTransaction(Agent *agent, TransactionCallback callback, void *magic) :
		Transaction(agent, callback, magic), outgoing(NULL) {
	LOGD("New OutgoingTransaction %p", this);

}

OutgoingTransaction::~OutgoingTransaction() {
	if (outgoing != NULL) {
		nta_outgoing_bind(outgoing, NULL, NULL); //avoid callbacks
		nta_outgoing_destroy(outgoing);
	}
	LOGD("Destroy OutgoingTransaction %p", this);
}

void OutgoingTransaction::send(StatefulSipEvent *ev) {
	msg_ref_create(ev->getMsgSip()->getMsg());
	outgoing = nta_outgoing_mcreate(agent->mAgent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, NULL, ev->getMsgSip()->getMsg(), TAG_END());
	if (outgoing == NULL) {
		msg_destroy(ev->getMsgSip()->getMsg());
	}
	ev->terminateProcessing();
}

int OutgoingTransaction::_callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip) {
	OutgoingTransaction * it = reinterpret_cast<OutgoingTransaction *>(magic);
	if (it->callback != NULL) {
		it->callback(sip, it);
	}
	return 0;
}

nta_outgoing_t *OutgoingTransaction::getOutgoing() {
	return outgoing;
}

IncomingTransaction::IncomingTransaction(Agent *agent, msg_t * msg, sip_t *sip, TransactionCallback callback, void *magic) :
		Transaction(agent, callback, magic), incoming(NULL) {
	msg_ref_create(msg);
	incoming = nta_incoming_create(agent->mAgent, NULL, msg, sip, TAG_END());
	nta_incoming_bind(incoming, IncomingTransaction::_callback, (nta_incoming_magic_t*) this);
	LOGD("New IncomingTransaction %p", this);
}

IncomingTransaction::~IncomingTransaction() {
	if (incoming != NULL) {
		nta_incoming_bind(incoming, NULL, NULL); //avoid callbacks
		nta_incoming_destroy(incoming);
	}
	LOGD("Destroy IncomingTransaction %p", this);
}

void IncomingTransaction::send(StatefulSipEvent *ev) {
	msg_ref_create(ev->getMsgSip()->getMsg());
	nta_incoming_mreply(incoming, ev->getMsgSip()->getMsg());
	ev->terminateProcessing();
}

int IncomingTransaction::_callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip) {
	IncomingTransaction * it = reinterpret_cast<IncomingTransaction *>(magic);
	if (it->callback != NULL) {
		it->callback(sip, it);
	}
	return 0;
}

nta_incoming_t *IncomingTransaction::getIncoming() {
	return incoming;
}
