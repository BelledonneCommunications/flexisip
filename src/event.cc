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

StatefulSipEvent::StatefulSipEvent(Transaction *transaction, msg_t *msg, sip_t *sip) :
		SipEvent(msg, sip), transaction(transaction) {

}

StatefulSipEvent::~StatefulSipEvent() {

}

Transaction* StatefulSipEvent::getTransaction() {
	return transaction;
}
