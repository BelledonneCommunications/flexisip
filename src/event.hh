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

#include <memory>
#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>

class Agent;
class Module;
class IncomingTransaction;
class OutgoingTransaction;
class IncomingTransactionHandler;
class OutgoingTransactionHandler;

class MsgSip {
public:
	MsgSip(msg_t *msg, sip_t *sip = NULL);
	MsgSip(const MsgSip &msgSip);
	~MsgSip();

	inline msg_t* getMsg() const {
		return mMsg;
	}

	inline sip_t* getSip() const {
		return mSip;
	}

	inline su_home_t* getHome() const {
		return mHome;
	}

private:
	su_home_t *mHome;
	msg_t *mMsg;
	sip_t *mSip;
};

class SipEvent {
	friend class StatelessSipEvent;
	friend class StatefulSipEvent;
	friend class Agent;
public:

	SipEvent(std::shared_ptr<MsgSip> msgSip);
	SipEvent(const SipEvent &sipEvent);

	inline std::shared_ptr<MsgSip> getMsgSip() const {
		return mMsgSip;
	}

	inline void setMsgSip(std::shared_ptr<MsgSip> msgSip) {
		mMsgSip = msgSip;
	}

	void terminateProcessing();

	void suspendProcessing();

	void restartProcessing();

	inline bool isSuspended() const {
		return mState == SUSPENDED;
	}

	inline bool isTerminated() const {
		return mState == TERMINATED;
	}

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual void send(const std::shared_ptr<MsgSip> &msg) = 0;

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) = 0;

	virtual ~SipEvent() {

	}

protected:
	Module *mCurrModule;
	std::shared_ptr<MsgSip> mMsgSip;

	enum {
		STARTED, SUSPENDED, TERMINATED,
	} mState;
};

class StatelessSipEvent: public SipEvent {
public:
	StatelessSipEvent(const std::shared_ptr<SipEvent> &SipEvent);
	StatelessSipEvent(Agent *agent, const std::shared_ptr<MsgSip> &msgSip);

	inline Agent* getAgent() const {
		return mAgent;
	}

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

	virtual ~StatelessSipEvent();
private:
	Agent *mAgent;
};

class Transaction;
class StatefulSipEvent: public SipEvent {
public:
	StatefulSipEvent(const std::shared_ptr<Transaction> &transaction, const std::shared_ptr<SipEvent> &sipEvent);
	StatefulSipEvent(const std::shared_ptr<Transaction> &transaction, const std::shared_ptr<MsgSip> &msgSip);

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

	~StatefulSipEvent();
private:
	std::shared_ptr<Transaction> transaction;
};

class NullSipEvent: public SipEvent {
public:
	NullSipEvent(const std::shared_ptr<SipEvent> &sipEvent);
	NullSipEvent(const std::shared_ptr<MsgSip> &msgSip);

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);
	~NullSipEvent();
};

#endif //event_hh
