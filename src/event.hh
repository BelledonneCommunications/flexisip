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

#ifndef event_hh
#define event_hh

#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>

class Module;

class SipEvent {
	friend class Agent;
public:
	SipEvent(msg_t *msg, sip_t *sip = NULL);
	SipEvent(const SipEvent *sipEvent);

	void terminateProcessing();

	void suspendProcessing();

	void restartProcessing();

	bool suspended() const;

	bool terminated() const;

	inline msg_t* getMsg() const {
		return mMsg;
	}

	inline sip_t* getSip() const {
		return mSip;
	}

	inline su_home_t* getHome() const {
		return mHome;
	}

	void setMsgSip(msg_t *msg, sip_t *sip = NULL);
	const Module *getCurrentModule() { return mCurrModule;}

	virtual ~SipEvent();
private:
	Module *mCurrModule;
	enum {
		STARTED, SUSPENDED, TERMINATED,
	} mState;
	su_home_t *mHome;
	msg_t *mMsg;
	sip_t *mSip;
};

class Transaction;
class StatefulSipEvent: public SipEvent {
private:
	Transaction *transaction;
public:
	StatefulSipEvent(Transaction *transaction, msg_t *msg, sip_t *sip);
	StatefulSipEvent(Transaction *transaction, const SipEvent *sipEvent);
	Transaction *getTransaction();
	~StatefulSipEvent();
};

#endif //event_hh
