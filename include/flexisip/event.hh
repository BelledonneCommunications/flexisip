/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <list>
#include <memory>
#include <regex.h>
#include <string>

#include "sofia-sip/nta.h"
#include "sofia-sip/sip.h"
#include "sofia-sip/tport.h"

#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/utils/sip-uri.hh"

namespace flexisip {

class Agent;
class Module;
class IncomingAgent;
class OutgoingAgent;
class IncomingTransaction;
class OutgoingTransaction;
class EventLog;
class EventLogWriteDispatcher;
class SocketAddress;

using MsgSip = sofiasip::MsgSip;

class SipEvent {
	friend class Agent;

public:
	SipEvent(const std::shared_ptr<IncomingAgent>& inAgent,
	         const std::shared_ptr<MsgSip>& msgSip,
	         tport_t* tport = nullptr);
	SipEvent(const std::shared_ptr<OutgoingAgent>& outAgent,
	         const std::shared_ptr<MsgSip>& msgSip,
	         tport_t* tport = nullptr);
	SipEvent(const SipEvent& sipEvent);

	inline const std::shared_ptr<MsgSip>& getMsgSip() const {
		return mMsgSip;
	}

	inline su_home_t* getHome() const {
		return mMsgSip->getHome();
	}
	inline sip_t* getSip() const {
		return mMsgSip->getSip();
	}

	virtual void terminateProcessing();

	virtual void suspendProcessing();

	virtual void restartProcessing();

	inline bool isSuspended() const {
		return mState == State::SUSPENDED;
	}

	inline bool isTerminated() const {
		return mState == State::TERMINATED;
	}

	std::shared_ptr<IncomingAgent> getIncomingAgent() const;

	std::shared_ptr<OutgoingAgent> getOutgoingAgent() const;

	virtual inline void setIncomingAgent(const std::shared_ptr<IncomingAgent>& agent) {
		mIncomingAgent = agent;
	}

	virtual inline void setOutgoingAgent(const std::shared_ptr<OutgoingAgent>& agent) {
		mOutgoingAgent = agent;
	}

	virtual void send(const std::shared_ptr<MsgSip>& msg,
	                  url_string_t const* u = nullptr,
	                  tag_type_t tag = nullptr,
	                  tag_value_t value = 0,
	                  ...) = 0;

	virtual ~SipEvent();

	const std::weak_ptr<Module>& getCurrentModule() {
		return mCurrModule;
	}

	template <typename _eventLogT>
	std::shared_ptr<_eventLogT> getEventLog() {
		return std::dynamic_pointer_cast<_eventLogT>(mEventLog);
	}
	void setEventLog(const std::shared_ptr<EventLog>& log);
	void flushLog(); /*to be used exceptionally when an event log needs to be flushed immediately, for example because
	                    you need to submit a new one.*/
	// Write given EventLog immediately
	void writeLog(const std::shared_ptr<const EventLogWriteDispatcher>&);
	std::shared_ptr<IncomingTransaction> getIncomingTransaction();
	std::shared_ptr<OutgoingTransaction> getOutgoingTransaction();

	const std::shared_ptr<tport_t>& getIncomingTport() const;
	std::shared_ptr<SocketAddress> getMsgAddress() const;

	int getStatusCode() const;

protected:
	enum class State {
		STARTED,
		SUSPENDED,
		TERMINATED,
	};

	static std::string stateStr(State s) {
		switch (s) {
			case State::STARTED:
				return "STARTED";
			case State::SUSPENDED:
				return "SUSPENDED";
			case State::TERMINATED:
				return "TERMINATED";
		}
		return "invalid";
	}

	std::weak_ptr<Module> mCurrModule;
	std::shared_ptr<MsgSip> mMsgSip;
	std::shared_ptr<EventLog> mEventLog;
	std::weak_ptr<Agent> mAgent;
	State mState;

private:
	std::shared_ptr<tport_t> mIncomingTport;
	std::weak_ptr<IncomingAgent> mIncomingAgent;
	std::weak_ptr<OutgoingAgent> mOutgoingAgent;
	std::string mLogPrefix;
};

class RequestSipEvent : public SipEvent {
public:
	RequestSipEvent(std::shared_ptr<IncomingAgent> incomingAgent,
	                const std::shared_ptr<MsgSip>& msgSip,
	                tport_t* tport = nullptr);
	RequestSipEvent(const RequestSipEvent& sipEvent);

	// Sip event extends enable_shared_from_this and constructor should be private.
	static std::unique_ptr<RequestSipEvent> makeRestored(std::shared_ptr<IncomingAgent> incomingAgent,
	                                                     const std::shared_ptr<MsgSip>& msgSip,
	                                                     const std::weak_ptr<Module>& currModule);

	void suspendProcessing() override;
	void terminateProcessing() override;
	std::shared_ptr<IncomingTransaction> createIncomingTransaction();
	std::shared_ptr<OutgoingTransaction> createOutgoingTransaction();

	void send(const std::shared_ptr<MsgSip>& msg,
	          url_string_t const* u = nullptr,
	          tag_type_t tag = nullptr,
	          tag_value_t value = 0,
	          ...) override;

	void reply(int status, char const* phrase, tag_type_t tag, tag_value_t value, ...);

	void setIncomingAgent(const std::shared_ptr<IncomingAgent>& agent) override;

	~RequestSipEvent();

	/** Find if incoming tport TLS client certificate contains a given entry */
	bool findIncomingSubject(const char* searched) const;
	const char* findIncomingSubject(const std::list<std::string>& in) const;
	bool matchIncomingSubject(regex_t* regex);
	void unlinkTransactions();
	bool mRecordRouteAdded;

	struct AuthResult {
		enum class Type { Bearer, Digest, TLS };
		enum class Result { Invalid, Valid };
		class ChallengeResult {
		public:
			explicit ChallengeResult(Type type) : mType(type) {
			}
			void setIdentity(const SipUri& sipUri) {
				mIdentity = sipUri;
			}
			void accept() {
				mResult = Result::Valid;
			}
			Type getType() const {
				return mType;
			}
			const SipUri& getIdentity() const {
				return mIdentity;
			}
			Result getResult() const {
				return mResult;
			}

		private:
			Type mType{};
			SipUri mIdentity{};
			Result mResult{Result::Invalid};
		};
		bool trustedHost{};
		std::list<ChallengeResult> challenges;
	};

	void setTrustedHost() {
		mAuthResult.trustedHost = true;
	}
	void addChallengeResult(AuthResult::ChallengeResult&& challenge) {
		mAuthResult.challenges.push_back(std::move(challenge));
	}
	const AuthResult& getAuthResult() const {
		return mAuthResult;
	}

private:
	void checkContentLength(const url_t* url);
	void linkTransactions();

	AuthResult mAuthResult{};
	// keep ownership of transactions
	std::shared_ptr<IncomingTransaction> mIncomingTransactionOwner;
	std::shared_ptr<OutgoingTransaction> mOutgoingTransactionOwner;
	std::string mLogPrefix;
};

class ResponseSipEvent : public SipEvent {
public:
	ResponseSipEvent(std::shared_ptr<OutgoingAgent> outgoingAgent,
	                 const std::shared_ptr<MsgSip>& msgSip,
	                 tport_t* tport = nullptr);
	ResponseSipEvent(const ResponseSipEvent& sipEvent);

	void send(const std::shared_ptr<MsgSip>& msg,
	          url_string_t const* u = nullptr,
	          tag_type_t tag = nullptr,
	          tag_value_t value = 0,
	          ...) override;

	void setOutgoingAgent(const std::shared_ptr<OutgoingAgent>& agent) override;

	~ResponseSipEvent();

private:
	void checkContentLength(const std::shared_ptr<MsgSip>& msg, const sip_via_t* via);
	bool mPopVia; // set to true if the response comes from an outgoing transaction.
	std::string mLogPrefix;
};

} // namespace flexisip