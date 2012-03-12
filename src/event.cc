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
	mMsg = msg_copy(msg);
	mSip = sip_object(mMsg);
	mHome = msg_home(mMsg);
}

MsgSip::MsgSip(const MsgSip &msgSip) {
	mMsg = msg_copy(msgSip.mMsg);
	mSip = sip_object(mMsg);
	mHome = msg_home(mMsg);
}

MsgSip::~MsgSip() {
	msg_destroy(mMsg);
}

SipEvent::SipEvent(std::shared_ptr<MsgSip> msgSip) :
		mCurrModule(NULL), mMsgSip(msgSip), mState(STARTED) {
}

SipEvent::SipEvent(const SipEvent &sipEvent) :
		mCurrModule(sipEvent.mCurrModule), mMsgSip(sipEvent.mMsgSip), mState(sipEvent.mState) {

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

StatelessSipEvent::StatelessSipEvent(Agent *agent, const shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip), mAgent(agent) {
}

void StatelessSipEvent::send(const shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	msg_ref_create(msg->getMsg());
	nta_msg_tsend(mAgent->mAgent, msg->getMsg(), u, ta_tags(ta));
	ta_end(ta);
	terminateProcessing();
}

void StatelessSipEvent::send(const shared_ptr<MsgSip> &msg) {
	msg_ref_create(msg->getMsg());
	nta_msg_tsend(mAgent->mAgent, msg->getMsg(), NULL, TAG_END());
}

void StatelessSipEvent::reply(const shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	msg_ref_create(msg->getMsg());
	nta_msg_treply(mAgent->mAgent, msg->getMsg(), status, phrase, ta_tags(ta));
	ta_end(ta);
	terminateProcessing();
}

StatelessSipEvent::~StatelessSipEvent() {
}

StatefulSipEvent::StatefulSipEvent(const std::shared_ptr<Transaction> &transaction, const shared_ptr<SipEvent> &sipEvent) :
		SipEvent(*sipEvent), transaction(transaction) {

}
StatefulSipEvent::StatefulSipEvent(const std::shared_ptr<Transaction> &transaction, const shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip), transaction(transaction) {

}

void StatefulSipEvent::send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	transaction->send(msg, u, ta_tags(ta));
	ta_end(ta);
	terminateProcessing();
}

void StatefulSipEvent::send(const std::shared_ptr<MsgSip> &msg) {
	transaction->send(msg);
	terminateProcessing();
}

void StatefulSipEvent::reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	transaction->reply(msg, status, phrase, ta_tags(ta));
	ta_end(ta);
	terminateProcessing();
}

StatefulSipEvent::~StatefulSipEvent() {

}

NullSipEvent::NullSipEvent(const std::shared_ptr<SipEvent> &sipEvent) :
		SipEvent(*sipEvent) {

}
NullSipEvent::NullSipEvent(const std::shared_ptr<MsgSip> &msgSip) :
		SipEvent(msgSip) {

}

void NullSipEvent::send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	terminateProcessing();
}
void NullSipEvent::send(const std::shared_ptr<MsgSip> &msg) {
	terminateProcessing();
}
void NullSipEvent::reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	terminateProcessing();
}

NullSipEvent::~NullSipEvent() {

}
