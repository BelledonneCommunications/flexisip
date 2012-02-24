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

#include "event.hh"
#include "common.hh"

SipEvent::SipEvent(msg_t *msg, sip_t *sip) :
		mCurrModule(NULL) {
	mMsg = msg;
	mSip = sip;
	mState = STARTED;
	/* msg_t internal implementation "inherits" from su_home_t*/
	mHome = (su_home_t*) msg;
	msg_ref_create(mMsg);
}

void SipEvent::terminateProcessing() {
	if (mState == STARTED || mState == SUSPENDED) {
		mState = TERMINATED;
	} else {
		LOGA("Can't terminateProcessing: wrong state");
	}
}

void SipEvent::suspendProcessing() {
	if (mState == STARTED) {
		mState = SUSPENDED;
	} else {
		LOGA("Can't suspendProcessing: wrong state");
	}
}

void SipEvent::restartProcessing() {
	if (mState == SUSPENDED) {
		mState = STARTED;
	} else {
		LOGA("Can't restartProcessing: wrong state");
	}
}

bool SipEvent::suspended() const {
	return mState == SUSPENDED;
}

bool SipEvent::terminated() const {
	return mState == TERMINATED;
}

SipEvent::~SipEvent() {
	msg_destroy(mMsg);
}

su_home_t* SipEvent::getHome() {
	return mHome;
}

// // // //

StatefulSipEvent::StatefulSipEvent(Transaction *transaction, msg_t *msg, sip_t *sip) :
		SipEvent(msg, sip), transaction(transaction) {

}

StatefulSipEvent::~StatefulSipEvent() {

}

Transaction* StatefulSipEvent::getTransaction() {
	return transaction;
}

OutgoingTransaction::OutgoingTransaction(nta_agent_t *agent, msg_t * msg, sip_t *sip, TransactionCallback callback, void *magic) :
		Transaction(callback, magic), outgoing(NULL), agent(agent) {
	LOGD("New OutgoingTransaction %p", this);

}

OutgoingTransaction::~OutgoingTransaction() {
	if (outgoing != NULL) {
		nta_outgoing_bind(outgoing, NULL, NULL); //avoid callbacks
		nta_outgoing_destroy(outgoing);
	}
	LOGD("Destroy OutgoingTransaction %p", this);
}

StatefulSipEvent *OutgoingTransaction::create(msg_t * msg, sip_t *sip) {
	return new StatefulSipEvent(this, msg, sip);
}

void OutgoingTransaction::send(StatefulSipEvent *ev) {
	outgoing = nta_outgoing_mcreate(agent, OutgoingTransaction::_callback, (nta_outgoing_magic_t*) this, NULL, ev->mMsg, TAG_END());
	if (outgoing == NULL) {
		msg_destroy(ev->mMsg);
	}
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

IncomingTransaction::IncomingTransaction(nta_agent_t *agent, msg_t * msg, sip_t *sip, TransactionCallback callback, void *magic) :
		Transaction(callback, magic), incoming(NULL), leg(NULL), agent(agent) {
	//leg = nta_leg_tcreate(agent, IncomingTransaction::_callback, (nta_leg_magic_t*) this, SIPTAG_CALL_ID(sip->sip_call_id), SIPTAG_FROM(sip->sip_to), SIPTAG_TO(sip->sip_from), TAG_END());
	incoming = nta_incoming_create(agent, NULL, msg, sip, TAG_END());
	nta_incoming_bind(incoming, IncomingTransaction::_callback, (nta_incoming_magic_t*)this);
	LOGD("New IncomingTransaction %p", this);
}

IncomingTransaction::~IncomingTransaction() {
	if (incoming != NULL) {
		nta_incoming_destroy(incoming);
	}
	if (leg != NULL) {
		nta_leg_bind(leg, NULL, NULL);
		nta_leg_destroy(leg);
	}
	LOGD("Destroy IncomingTransaction %p", this);
}

StatefulSipEvent *IncomingTransaction::create(msg_t * msg, sip_t *sip) {
	return new StatefulSipEvent(this, msg, sip);
}

void IncomingTransaction::send(StatefulSipEvent *ev) {
	nta_incoming_mreply(incoming, ev->mMsg);
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
