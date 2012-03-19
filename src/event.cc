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

using namespace ::std;

MsgSip::MsgSip(msg_t *msg, sip_t *sip) {
	LOGD("New MsgSip %p", this);
	mMsg = msg_copy(msg);
	mSip = sip_object(mMsg);
	mHome = msg_home(mMsg);
}

MsgSip::MsgSip(const MsgSip &msgSip) {
	LOGD("New MsgSip %p", this);
	mMsg = msg_copy(msgSip.mMsg);
	mSip = sip_object(mMsg);
	mHome = msg_home(mMsg);
}

void MsgSip::log(const char * header) {
	if (IS_LOGD) {
		su_home_t home;
		size_t msg_size;
		char *buf;

		su_home_init(&home);
		buf = msg_as_string(&home, mMsg, NULL, 0, &msg_size);
		LOGD("%s%s%s", (header) ? header : "", (header) ? "\n" : "", buf);
		su_home_deinit(&home);
	}
}

MsgSip::~MsgSip() {
	LOGD("Destroy MsgSip %p", this);
	msg_destroy(mMsg);
}

SipEvent::SipEvent(const std::shared_ptr<MsgSip> msgSip) :
		mCurrModule(NULL), mMsgSip(msgSip), mState(STARTED) {
}

SipEvent::SipEvent(const SipEvent &sipEvent) :
		mCurrModule(sipEvent.mCurrModule), mMsgSip(sipEvent.mMsgSip), mIncomingAgent(sipEvent.mIncomingAgent), mOutgoingAgent(sipEvent.mOutgoingAgent), mState(sipEvent.mState) {

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

shared_ptr<IncomingTransaction> SipEvent::createIncomingTransaction() {
	shared_ptr<IncomingTransaction> transaction = dynamic_pointer_cast<IncomingTransaction>(mIncomingAgent);
	if (transaction == NULL) {
		transaction = shared_ptr<IncomingTransaction>(new IncomingTransaction(mIncomingAgent->getAgent()));
		transaction->handle(mMsgSip);
		mIncomingAgent = transaction;
	}
	return transaction;
}

shared_ptr<OutgoingTransaction> SipEvent::createOutgoingTransaction() {
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(mOutgoingAgent);
	if (transaction == NULL) {
		transaction = shared_ptr<OutgoingTransaction>(new OutgoingTransaction(mOutgoingAgent->getAgent()));
		mOutgoingAgent = transaction;
	}
	return transaction;
}

RequestSipEvent::RequestSipEvent(const shared_ptr<IncomingAgent> &incomingAgent, const shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip) {
	mIncomingAgent = incomingAgent;
	mOutgoingAgent = incomingAgent->getAgent()->shared_from_this();
}

RequestSipEvent::RequestSipEvent(const std::shared_ptr<SipEvent> &sipEvent, const std::shared_ptr<MsgSip> &msgSip) :
		SipEvent(*sipEvent) {
	mMsgSip = msgSip;
}

void RequestSipEvent::send(const shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	if (mOutgoingAgent != NULL) {
		msg->log("Sending Request SIP message:");
		ta_list ta;
		ta_start(ta, tag, value);
		mOutgoingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	}
	terminateProcessing();
}

void RequestSipEvent::send(const shared_ptr<MsgSip> &msg) {
	if (mOutgoingAgent != NULL) {
		msg->log("Sending Request SIP message:");
		mOutgoingAgent->send(msg);
	}
	terminateProcessing();
}

void RequestSipEvent::reply(const shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	if (mIncomingAgent != NULL) {
		LOGD("Replying Request SIP message: %i %s\n\n", status, phrase);
		ta_list ta;
		ta_start(ta, tag, value);
		mIncomingAgent->reply(msg, status, phrase, ta_tags(ta));
		ta_end(ta);
	}
	terminateProcessing();
}

void RequestSipEvent::setIncomingAgent(const std::shared_ptr<IncomingAgent> &agent) {
	LOGA("Can't change incoming agent in request sip event");
}

RequestSipEvent::~RequestSipEvent() {
}

ResponseSipEvent::ResponseSipEvent(const shared_ptr<OutgoingAgent> &outgoingAgent, const shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip) {
	mOutgoingAgent = outgoingAgent;
	mIncomingAgent = outgoingAgent->getAgent()->shared_from_this();
}

ResponseSipEvent::ResponseSipEvent(const std::shared_ptr<SipEvent> &sipEvent, const std::shared_ptr<MsgSip> &msgSip) :
		SipEvent(*sipEvent) {
	mMsgSip = msgSip;
}

void ResponseSipEvent::send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	if (mIncomingAgent != NULL) {
		msg->log("Sending Response SIP message:");
		ta_list ta;
		ta_start(ta, tag, value);
		mIncomingAgent->send(msg, u, ta_tags(ta));
		ta_end(ta);
	}
	terminateProcessing();
}

void ResponseSipEvent::send(const std::shared_ptr<MsgSip> &msg) {
	if (mIncomingAgent != NULL) {
		msg->log("Sending Response SIP message:");
		mIncomingAgent->send(msg);
	}
	terminateProcessing();
}

void ResponseSipEvent::reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	LOGA("Can't reply to an response sip event");
}

void ResponseSipEvent::setOutgoingAgent(const std::shared_ptr<OutgoingAgent> &agent) {
	LOGA("Can't change outgoing agent in response sip event");
}

ResponseSipEvent::~ResponseSipEvent() {

}
