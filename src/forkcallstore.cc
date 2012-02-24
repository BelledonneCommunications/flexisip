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
		agent(agent), module(module) {
	LOGD("New ForkCallContext %p", this);
}

ForkCallContext::~ForkCallContext() {
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

void ForkCallContext::receiveOk(Transaction *transaction) {
	OutgoingTransaction *outgoing_transaction = dynamic_cast<OutgoingTransaction *>(transaction);
	if (outgoing_transaction != NULL) {
		LOGD("Ok from %p", outgoing_transaction);
		msg_t *msg = msg_copy(nta_outgoing_getresponse(outgoing_transaction->getOutgoing()));
		std::shared_ptr<SipEvent> ev(incoming->create(msg, sip_object(msg)));
		ev->suspendProcessing();
		agent->injectResponseEvent(ev, module);

		// Cancel others
		for (std::list<OutgoingTransaction *>::iterator it = outgoings.begin(); it != outgoings.end();) {
			std::list<OutgoingTransaction *>::iterator old_it = it;
			++it;
			if (*old_it != outgoing_transaction) {
				OutgoingTransaction *ot = *old_it;
				LOGD("Fork: cancel %p", ot->getOutgoing());
				nta_outgoing_tcancel(ot->getOutgoing(), NULL, NULL, TAG_END());
			}
		}
	} else {
		LOGW("receiveOk only on Outgoing");
	}
}

void ForkCallContext::receiveInvite(Transaction *transaction) {
	IncomingTransaction *incoming_transaction = dynamic_cast<IncomingTransaction *>(transaction);
	if (incoming_transaction != NULL) {
		nta_incoming_treply(incoming_transaction->getIncoming(), SIP_100_TRYING, TAG_END());
	} else {
		LOGW("receiveInvite only on Incoming");
	}
}

void ForkCallContext::receiveCancel(Transaction *transaction) {
	IncomingTransaction *incoming_transaction = dynamic_cast<IncomingTransaction *>(transaction);
	if (incoming_transaction != NULL) {
		// Cancel all
		for (std::list<OutgoingTransaction *>::iterator it = outgoings.begin(); it != outgoings.end();) {
			std::list<OutgoingTransaction *>::iterator old_it = it;
			++it;
			OutgoingTransaction *ot = *old_it;
			LOGD("Fork: Cancel %p", ot->getOutgoing());
			nta_outgoing_tcancel(ot->getOutgoing(), NULL, NULL, TAG_END());
		}
		nta_incoming_treply(incoming_transaction->getIncoming(), SIP_200_OK, TAG_END());
	} else {
		LOGW("receiveCancel only on Incoming");
	}
}

void ForkCallContext::receiveTimeout(Transaction *transaction) {
	OutgoingTransaction *outgoing_transaction = dynamic_cast<OutgoingTransaction *>(transaction);
	if (outgoing_transaction != NULL) {
		deleteOutgoingTransaction(outgoing_transaction);
		return;
	}

	IncomingTransaction *incoming_transaction = dynamic_cast<IncomingTransaction *>(transaction);
	if (incoming_transaction != NULL) {
		deleteIncomingTransaction(incoming_transaction);
		return;
	}

	LOGW("Fork: Invalid Transaction");
}

void ForkCallContext::receiveBye(Transaction *transaction) {
	OutgoingTransaction *outgoing_transaction = dynamic_cast<OutgoingTransaction *>(transaction);
	if (outgoing_transaction != NULL) {
		deleteOutgoingTransaction(outgoing_transaction);
		return;
	}

	IncomingTransaction *incoming_transaction = dynamic_cast<IncomingTransaction *>(transaction);
	if (incoming_transaction != NULL) {
		deleteIncomingTransaction(incoming_transaction);
		return;
	}

	LOGW("Fork: Invalid Transaction");
}

void ForkCallContext::deleteOutgoingTransaction(OutgoingTransaction *transaction) {
	if (transaction != NULL) {
		delete transaction;
		outgoings.remove(transaction);
		if (outgoings.size() == 0) {
			delete this;
		}
	}

}

void ForkCallContext::deleteIncomingTransaction(IncomingTransaction *transaction) {
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

