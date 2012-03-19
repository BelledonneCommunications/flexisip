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
class IncomingAgent;
class OutgoingAgent;
class IncomingTransaction;
class OutgoingTransaction;

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

	void log(const char * header);

private:
	su_home_t *mHome;
	msg_t *mMsg;
	sip_t *mSip;
};

class SipEvent {
	friend class Agent;
public:

	SipEvent(const std::shared_ptr<MsgSip> msgSip);
	SipEvent(const SipEvent &sipEvent);

	inline const std::shared_ptr<MsgSip> &getMsgSip() const {
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

	inline const std::shared_ptr<IncomingAgent>& getIncomingAgent() {
		return mIncomingAgent;
	}

	inline const std::shared_ptr<OutgoingAgent>& getOutgoingAgent() {
		return mOutgoingAgent;
	}

	std::shared_ptr<IncomingTransaction> createIncomingTransaction();

	std::shared_ptr<OutgoingTransaction> createOutgoingTransaction();

	virtual inline void setIncomingAgent(const std::shared_ptr<IncomingAgent> &agent) {
		mIncomingAgent = agent;
	}

	virtual inline void setOutgoingAgent(const std::shared_ptr<OutgoingAgent> &agent) {
		mOutgoingAgent = agent;
	}

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual void send(const std::shared_ptr<MsgSip> &msg) = 0;

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) = 0;

	virtual ~SipEvent() {

	}
	Module *getCurrentModule() { return mCurrModule; }

protected:
	Module *mCurrModule;
	std::shared_ptr<MsgSip> mMsgSip;
	std::shared_ptr<IncomingAgent> mIncomingAgent;
	std::shared_ptr<OutgoingAgent> mOutgoingAgent;

	enum {
		STARTED, SUSPENDED, TERMINATED,
	} mState;
};

class RequestSipEvent: public SipEvent {
public:
	RequestSipEvent(const std::shared_ptr<IncomingAgent> &incomingAgent, const std::shared_ptr<MsgSip> &msgSip);
	RequestSipEvent(const std::shared_ptr<SipEvent> &sipEvent, const std::shared_ptr<MsgSip> &msgSip);

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

	virtual void setIncomingAgent(const std::shared_ptr<IncomingAgent> &agent);

	~RequestSipEvent();
};

class ResponseSipEvent: public SipEvent {
public:
	ResponseSipEvent(const std::shared_ptr<OutgoingAgent> &outgoingAgent, const std::shared_ptr<MsgSip> &msgSip);
	ResponseSipEvent(const std::shared_ptr<SipEvent> &sipEvent, const std::shared_ptr<MsgSip> &msgSip);

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

	virtual void setOutgoingAgent(const std::shared_ptr<OutgoingAgent> &agent);

	~ResponseSipEvent();
};

#endif //event_hh
