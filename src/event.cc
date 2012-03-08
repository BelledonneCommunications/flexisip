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
#include <sofia-sip/sip_protos.h>

SipEvent::SipEvent(msg_t *msg, sip_t *sip) :
		mCurrModule(NULL), mState(STARTED), mHome(NULL), mMsg(NULL), mSip(NULL) {
	setMsgSip(msg, sip);
}

SipEvent::SipEvent(const SipEvent *sipEvent) :
		mCurrModule(sipEvent->mCurrModule), mState(sipEvent->mState), mHome(NULL), mMsg(NULL), mSip(NULL) {
	setMsgSip(msg_copy(sipEvent->mMsg));
}

void SipEvent::setMsgSip(msg_t *msg, sip_t *sip) {
	msg_t* old_msg = mMsg;

	mMsg = msg;
	mSip = (sip != NULL) ? sip : sip_object(msg);
	mHome = msg_home(msg);

	if (mMsg != NULL)
		msg_ref_create(mMsg);

	if (old_msg != NULL) {
		msg_ref_destroy(old_msg);
	}
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

StatefulSipEvent::StatefulSipEvent(Transaction *transaction, msg_t *msg, sip_t *sip) :
		SipEvent(msg, sip), transaction(transaction) {

}

StatefulSipEvent::StatefulSipEvent(Transaction *transaction, const SipEvent *sipEvent) :
		SipEvent(sipEvent), transaction(transaction) {

}

StatefulSipEvent::~StatefulSipEvent() {

}

Transaction* StatefulSipEvent::getTransaction() {
	return transaction;
}
