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

#include "forkcallstore.hh"
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>

ForkCallContext::ForkCallContext(Agent *agent, Module *module) :
		agent(agent), module(module), state(INITIAL) {
	LOGD("New ForkCallContext %p", this);
}

ForkCallContext::~ForkCallContext() {
	if (incoming != NULL)
		delete incoming;
	for_each(outgoings.begin(), outgoings.end(), delete_functor<OutgoingTransaction>());
	LOGD("Destroy ForkCallContext %p", this);
}

void ForkCallContext::setIncomingTransaction(IncomingTransaction *transaction) {
	incoming = transaction;
}

void ForkCallContext::addOutgoingTransaction(OutgoingTransaction *transaction) {
	outgoings.push_back(transaction);
}

void ForkCallContext::receiveOk(OutgoingTransaction *transaction) {
	msg_t *msg = nta_outgoing_getresponse(transaction->getOutgoing());
	sip_via_remove(msg, sip_object(msg)); // remove via @see test_proxy.c from sofia
	std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
	agent->sendResponseEvent(ev);

	// Cancel others
	for (std::list<OutgoingTransaction *>::iterator it = outgoings.begin(); it != outgoings.end();) {
		std::list<OutgoingTransaction *>::iterator old_it = it;
		++it;
		if (*old_it != transaction) {
			OutgoingTransaction *ot = *old_it;
			nta_outgoing_tcancel(ot->getOutgoing(), NULL, NULL, TAG_END());
			deleteTransaction(ot);
		}
	}

	deleteTransaction(incoming);
}

void ForkCallContext::receiveInvite(IncomingTransaction *transaction) {
	if (outgoings.size()) {
		msg_t *msg = nta_incoming_create_response(transaction->getIncoming(), SIP_100_TRYING);
		std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
		agent->sendResponseEvent(ev);
		state = INVITED;
	} else {
		msg_t *msg = nta_incoming_create_response(transaction->getIncoming(), SIP_404_NOT_FOUND);
		std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
		agent->sendResponseEvent(ev);
		deleteTransaction(transaction);
	}
}

void ForkCallContext::receiveCancel(IncomingTransaction *transaction) {
	for (std::list<OutgoingTransaction *>::iterator it = outgoings.begin(); it != outgoings.end();) {
		std::list<OutgoingTransaction *>::iterator old_it = it;
		++it;
		OutgoingTransaction *ot = *old_it;
		nta_outgoing_tcancel(ot->getOutgoing(), NULL, NULL, TAG_END());
		deleteTransaction(ot);
	}
	msg_t *msg = nta_incoming_create_response(transaction->getIncoming(), SIP_200_OK);
	std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
	agent->sendResponseEvent(ev);
	deleteTransaction(transaction);
}

void ForkCallContext::receiveTimeout(OutgoingTransaction *transaction) {
	deleteTransaction(transaction);

	if (outgoings.size() == 0) {
		msg_t *msg = nta_incoming_create_response(incoming->getIncoming(), SIP_408_REQUEST_TIMEOUT);
		std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
		agent->sendResponseEvent(ev);
		deleteTransaction(incoming);
	}
}

void ForkCallContext::receiveBye(IncomingTransaction *transaction) {
	deleteTransaction(transaction);
}

void ForkCallContext::receiveDecline(OutgoingTransaction *transaction) {
	deleteTransaction(transaction);

	if (outgoings.size() == 0) {
		msg_t *msg = nta_incoming_create_response(incoming->getIncoming(), SIP_603_DECLINE);
		std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
		agent->sendResponseEvent(ev);
		deleteTransaction(incoming);
	}
}

void ForkCallContext::receiveRinging(OutgoingTransaction *transaction) {
	if (state == INVITED) {
		msg_t *msg = nta_incoming_create_response(incoming->getIncoming(), SIP_180_RINGING);
		std::shared_ptr<SipEvent> ev(new StatefulSipEvent(incoming, msg, sip_object(msg)));
		agent->sendResponseEvent(ev);
		state = RINGING;
	}
}

void ForkCallContext::deleteTransaction(OutgoingTransaction *transaction) {
	if (transaction != NULL) {
		delete transaction;
		outgoings.remove(transaction);
	}
}

void ForkCallContext::deleteTransaction(IncomingTransaction *transaction) {
	if (transaction != NULL) {
		delete transaction;
		incoming = NULL;
		delete this;
	}

}

void ForkCallStore::addForkCall(long id, ForkCallContext* forkcall) {
	mForkCallContexts.insert(std::pair<long, ForkCallContext*>(id, forkcall));
}

ForkCallContext* ForkCallStore::getForkCall(long id) {
	std::map<long, ForkCallContext*>::iterator it = mForkCallContexts.find(id);
	if (it != mForkCallContexts.end())
		return it->second;
	else
		return NULL;
}

void ForkCallStore::removeForkCall(long id) {
	std::map<long, ForkCallContext*>::iterator it = mForkCallContexts.find(id);
	if (it != mForkCallContexts.end()) {
		delete it->second;
		mForkCallContexts.erase(it);
	}
}

ForkCallStore::ForkCallStore() {

}

ForkCallStore::~ForkCallStore() {
	for_each(mForkCallContexts.begin(), mForkCallContexts.end(), map_delete_functor<long, ForkCallContext*>());
}

