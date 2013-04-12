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

#include "agent.hh"
#include "event.hh"
#include "transaction.hh"
#include "common.hh"
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/msg_addr.h>

using namespace ::std;

void MsgSip::defineMsg(msg_t *msg) {
	mMsg = msg_copy(msg);
	msg_addr_copy(mMsg, msg);
	mSip = sip_object(mMsg);
	mHome = msg_home(mMsg);
	mOriginal = false;
}

MsgSip::MsgSip(msg_t *msg) {
//	LOGD("New MsgSip %p with reference to msg %p", this, msg);
	mOriginalMsg = msg_ref_create(msg);
	defineMsg(mOriginalMsg);
	mOriginal = true;
}

MsgSip::MsgSip(const MsgSip &msgSip) {
//	LOGD("New MsgSip %p with swallow copy %p of msg %p", this, mMsg, msgSip.mMsg);
	msgSip.serialize();
	defineMsg(msgSip.mMsg);
	mOriginalMsg = msg_ref_create(msgSip.mOriginalMsg);
}

MsgSip::MsgSip(const MsgSip &msgSip, msg_t *msg) {
	defineMsg(msg);
	mOriginalMsg = msg_ref_create(msgSip.mOriginalMsg);
}


void MsgSip::log(const char *fmt, ...) {
	if (IS_LOGD) {
		size_t msg_size;
		char *header = NULL;
		char *buf = NULL;
		if (fmt) {
			va_list args;
			va_start(args, fmt);
			header = su_vsprintf(mHome, fmt, args);
			va_end(args);
		}
		msg_serialize(mMsg,(msg_pub_t*)mSip); //make sure the message is serialized before showing it; it can be very confusing.
		buf = msg_as_string(mHome, mMsg, NULL, 0, &msg_size);
		LOGD("%s%s%s\nendmsg", (header) ? header : "", (header) ? "\n" : "", buf);
	}
}

MsgSip::~MsgSip() {
	//LOGD("Destroy MsgSip %p", this);
	msg_destroy(mMsg);
	msg_destroy(mOriginalMsg);
}

SipEvent::SipEvent(const shared_ptr<MsgSip> msgSip) :
		mCurrModule(NULL), mMsgSip(msgSip), mState(STARTED) {
	LOGD("New SipEvent %p", this);
}


SipEvent::SipEvent(const SipEvent &sipEvent) :
		mCurrModule(sipEvent.mCurrModule), mMsgSip(sipEvent.mMsgSip), mIncomingAgent(sipEvent.mIncomingAgent), mOutgoingAgent(sipEvent.mOutgoingAgent), mState(sipEvent.mState) {
	LOGD("New SipEvent %p with state %s", this, stateStr(mState).c_str());
}


SipEvent::~SipEvent() {
	//LOGD("Destroy SipEvent %p", this);
}

void SipEvent::terminateProcessing() {
	LOGD("Terminate SipEvent %p", this);
	if (mState == STARTED || mState == SUSPENDED) {
		mState = TERMINATED;
	} else {
		LOGA("Can't terminateProcessing: wrong state %s", stateStr(mState).c_str());
	}
}

void SipEvent::suspendProcessing() {
	LOGD("Suspend SipEvent %p", this);
	if (mState == STARTED) {
		mState = SUSPENDED;
	} else {
		LOGA("Can't suspendProcessing: wrong state %s", stateStr(mState).c_str());
	}
}

void SipEvent::restartProcessing() {
	LOGD("Restart SipEvent %p", this);
	if (mState == SUSPENDED) {
		mState = STARTED;
	} else {
		LOGA("Can't restartProcessing: wrong state %s", stateStr(mState).c_str());
	}
}

RequestSipEvent::RequestSipEvent(const shared_ptr<IncomingAgent> &incomingAgent, const shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip), mRecordRouteAdded(false) {
	mIncomingAgent = incomingAgent;
	mOutgoingAgent = incomingAgent->getAgent()->shared_from_this();
}

RequestSipEvent::RequestSipEvent(const shared_ptr<RequestSipEvent> &sipEvent) :
		SipEvent(*sipEvent), mRecordRouteAdded(sipEvent->mRecordRouteAdded) {
}

void RequestSipEvent::send(const shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	if (mOutgoingAgent != NULL) {
		if (IS_LOGD) {
			msg->log("Sending Request SIP message to=%s:", u ? url_as_string(msg->getHome(), (url_t const *) u) : NULL);
		}
		ta_list ta;
		ta_start(ta, tag, value);
		mOutgoingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGD("The Request SIP message is not send");
	}
	terminateProcessing();
}

void RequestSipEvent::send(const shared_ptr<MsgSip> &msg) {
	if (mOutgoingAgent != NULL) {
		if (IS_LOGD) {
			msg->log("Sending Request SIP message:");
		}
		mOutgoingAgent->send(msg);
	} else {
		LOGD("The Request SIP message is not send");
	}
	terminateProcessing();
}

void RequestSipEvent::reply(int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	if (mIncomingAgent != NULL) {
		if (IS_LOGD) {
			LOGD("Replying Request SIP message: %i %s\n\n", status, phrase);
		}
		ta_list ta;
		ta_start(ta, tag, value);
		mIncomingAgent->reply(getMsgSip(), status, phrase, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGD("The Request SIP message is not reply");
	}
	terminateProcessing();
}

void RequestSipEvent::setIncomingAgent(const shared_ptr<IncomingAgent> &agent) {
	LOGA("Can't change incoming agent in request sip event");
}

shared_ptr<IncomingTransaction> RequestSipEvent::createIncomingTransaction() {
	shared_ptr<IncomingTransaction> transaction = dynamic_pointer_cast<IncomingTransaction>(mIncomingAgent);
	if (transaction == NULL) {
		if (!mMsgSip->mOriginal) LOGA("It is too late to create an incoming transaction");
		transaction = shared_ptr<IncomingTransaction>(new IncomingTransaction(mIncomingAgent->getAgent()));
		mIncomingAgent = transaction;

		transaction->handle(mMsgSip);
	}
	return transaction;
}

shared_ptr<OutgoingTransaction> RequestSipEvent::createOutgoingTransaction() {
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(mOutgoingAgent);
	if (transaction == NULL) {
		transaction = shared_ptr<OutgoingTransaction>(new OutgoingTransaction(mOutgoingAgent->getAgent()));
		mOutgoingAgent = transaction;
	}
	return transaction;
}

void RequestSipEvent::suspendProcessing() {
	SipEvent::suspendProcessing();

	// Become stateful if not already the case.
	createIncomingTransaction();
}

RequestSipEvent::~RequestSipEvent() {
}

ResponseSipEvent::ResponseSipEvent(const shared_ptr<OutgoingAgent> &outgoingAgent, const shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip) {
	mOutgoingAgent = outgoingAgent;
	mIncomingAgent = outgoingAgent->getAgent()->shared_from_this();
}

ResponseSipEvent::ResponseSipEvent(const shared_ptr<SipEvent> &sipEvent) :
		SipEvent(*sipEvent) {
}

void ResponseSipEvent::send(const shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	if (mIncomingAgent != NULL) {
		if (IS_LOGD) {
			msg->log("Sending Response SIP message to=%s:", u ? url_as_string(msg->getHome(), (url_t const *) u) : NULL);
		}
		ta_list ta;
		ta_start(ta, tag, value);
		mIncomingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	} else {
		LOGD("The Response SIP message is not sent");
	}
	terminateProcessing();
}

void ResponseSipEvent::send(const shared_ptr<MsgSip> &msg) {
	if (mIncomingAgent != NULL) {
		if (IS_LOGD) {
			msg->log("Sending Response SIP message:");
		}
		mIncomingAgent->send(msg);
	} else {
		LOGD("The Response SIP message is not sent");
	}
	terminateProcessing();
}

void ResponseSipEvent::setOutgoingAgent(const shared_ptr<OutgoingAgent> &agent) {
	LOGA("Can't change outgoing agent in response sip event");
}

ResponseSipEvent::~ResponseSipEvent() {

}
