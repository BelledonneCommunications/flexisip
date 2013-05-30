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
#include <string>
#include <ostream>
#include <functional>
#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>

class Agent;
class Module;
class IncomingAgent;
class OutgoingAgent;
class IncomingTransaction;
class OutgoingTransaction;
class EventLog;
class SipAttributes;

class MsgSip {
	friend class Agent;
	friend class SipEvent;
	friend class RequestSipEvent;
	friend class ResponseSipEvent;
	friend class IncomingTransaction;
	friend class OutgoingTransaction;
public:
	MsgSip(const MsgSip &msgSip);
	MsgSip(const MsgSip &msgSip, msg_t *msg);
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
	void serialize()const{
		msg_serialize(mMsg,(msg_pub_t*)mSip);
	}
	msg_t *createOrigMsgRef() { return msg_ref_create(mOriginalMsg); }
	inline std::shared_ptr<SipAttributes> getSipAttr() { return mSipAttr; }
	const char *print();
private:
	MsgSip(msg_t *msg);
	void defineMsg(msg_t *msg);
	mutable su_home_t *mHome;
	msg_t *mOriginalMsg;
	msg_t *mMsg;
	sip_t *mSip;
	bool mOriginal;
	std::shared_ptr<SipAttributes> mSipAttr;
};

class SipEvent : public std::enable_shared_from_this<SipEvent>{
	friend class Agent;
public:

	SipEvent(const std::shared_ptr<MsgSip> msgSip);
	SipEvent(const SipEvent &sipEvent);

	inline const std::shared_ptr<MsgSip> &getMsgSip() const {
		return mMsgSip;
	}


	inline void setMsgSip(std::shared_ptr<MsgSip> msgSip) {
		mMsgSip = msgSip;
		mMsgSip->mOriginal = false;
	}

	virtual void terminateProcessing();

	virtual void suspendProcessing();

	virtual void restartProcessing();

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

	virtual inline void setIncomingAgent(const std::shared_ptr<IncomingAgent> &agent) {
		mIncomingAgent = agent;
	}

	virtual inline void setOutgoingAgent(const std::shared_ptr<OutgoingAgent> &agent) {
		mOutgoingAgent = agent;
	}

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual void send(const std::shared_ptr<MsgSip> &msg) = 0;

	virtual ~SipEvent();

	Module *getCurrentModule() { return mCurrModule; }
	
	template <typename _eventLogT> 
	std::shared_ptr<_eventLogT> getEventLog(){
		return std::dynamic_pointer_cast<_eventLogT>(mEventLog);
	}
	void setEventLog(const std::shared_ptr<EventLog> & log);
	void flushLog();/*to be used exceptionally when an eventlog needs to be flushed immediately, for example because you need to submit a new one.*/
protected:
	Module *mCurrModule;
	std::shared_ptr<MsgSip> mMsgSip;
	std::shared_ptr<IncomingAgent> mIncomingAgent;
	std::shared_ptr<OutgoingAgent> mOutgoingAgent;
	std::shared_ptr<EventLog> mEventLog;

	enum State {
		STARTED, SUSPENDED, TERMINATED,
	} mState;
	static std::string stateStr(State s) {
		switch (s) {
		case STARTED:
			return "STARTED";
		case SUSPENDED:
			return "SUSPENDED";
		case TERMINATED:
			return "TERMINATED";
		default:
			return "unknown";
		}
	}
private:
	
};

class RequestSipEvent: public SipEvent {
public:
	RequestSipEvent(const std::shared_ptr<IncomingAgent> &incomingAgent, const std::shared_ptr<MsgSip> &msgSip);
	RequestSipEvent(const std::shared_ptr<RequestSipEvent> &sipEvent);

	virtual void suspendProcessing();
	std::shared_ptr<IncomingTransaction> createIncomingTransaction();
	std::shared_ptr<OutgoingTransaction> createOutgoingTransaction();

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void reply(int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);

	virtual void setIncomingAgent(const std::shared_ptr<IncomingAgent> &agent);

	~RequestSipEvent();
	bool mRecordRouteAdded;
};

class ResponseSipEvent: public SipEvent {
public:
	ResponseSipEvent(const std::shared_ptr<OutgoingAgent> &outgoingAgent, const std::shared_ptr<MsgSip> &msgSip);
	ResponseSipEvent(const std::shared_ptr<SipEvent> &sipEvent);

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void send(const std::shared_ptr<MsgSip> &msg);

	virtual void setOutgoingAgent(const std::shared_ptr<OutgoingAgent> &agent);

	~ResponseSipEvent();
};

inline std::ostream& operator<<(std::ostream& strm, MsgSip const& obj) {
	// Here we hack out the constness.
	// The print method is non const as it will modify the underlying msg_t
	// during serialization. Moreover, the underlying sofia calls also take
	// a non const sip_t...
	MsgSip &hack=const_cast<MsgSip&>(obj);
	strm << hack.print();
	return strm;	
}

#endif //event_hh
