/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <flexisip/event.hh>

#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>

#include <string>
#include <map>

namespace flexisip {

class OutgoingTransaction;
class IncomingTransaction;
class Agent;

class IncomingAgent {
  public:
	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value,
					  ...) = 0;

	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag,
					   tag_value_t value, ...) = 0;

	virtual Agent *getAgent() = 0;

	virtual ~IncomingAgent();
};

class OutgoingAgent {
  public:
	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value,
					  ...) = 0;

	virtual Agent *getAgent() = 0;

	virtual ~OutgoingAgent();
};

class Transaction {
  protected:
	Agent *mAgent;
	typedef std::tuple<std::shared_ptr<void>, std::string> property_type;
	std::map<std::string, property_type> mProperties;
	void looseProperties() {
		mProperties.clear();
	}

  public:
	Transaction(Agent *agent) : mAgent(agent) {
	}

	~Transaction() {
	}

	Agent *getAgent() {
		return mAgent;
	}

	template <typename T> void setProperty(const std::string &name, std::shared_ptr<T> value) {
		std::string type_name = typeid(T).name();
		property_type prop = make_tuple(std::static_pointer_cast<void>(value), type_name);
		mProperties.insert(std::pair<std::string, property_type>(name, prop));
	}

	template <typename T> std::shared_ptr<T> getProperty(const std::string &name) {
		auto it = mProperties.find(name);
		if (it != mProperties.end()) {
			property_type &prop = it->second;
			if (std::get<1>(prop) == typeid(T).name()) {
				std::shared_ptr<T> tran = std::static_pointer_cast<T>(std::get<0>(prop));
				return tran;
			}
		}
		return std::shared_ptr<T>();
	}

	void removeProperty(const std::string &name) {
		auto it = mProperties.find(name);
		if (it != mProperties.end()) {
			mProperties.erase(it);
		}
	}
};

class OutgoingTransaction : public Transaction,
							public OutgoingAgent,
							public std::enable_shared_from_this<OutgoingTransaction> {
  public:
	// the use of make_shared() requires the constructor to be public, but don't use it. Use
	// RequestSipEvent::createOutgoingTransaction().
	OutgoingTransaction(Agent *agent);
	void cancel();
	void cancelWithReason(sip_reason_t* reason);
	const url_t *getRequestUri() const;
	const std::string &getBranchId() const;
	su_home_t* getHome();
	int getResponseCode() const;
	~OutgoingTransaction();
	std::shared_ptr<MsgSip> getRequestMsg();

	inline virtual Agent *getAgent() {
		return Transaction::getAgent();
	}
	/// The incoming transaction from which the message comes from, if any.
	std::shared_ptr<IncomingTransaction> mIncoming;
  private:
	friend class RequestSipEvent;
	static std::shared_ptr<OutgoingTransaction> create(Agent *agent);
	std::shared_ptr<OutgoingTransaction> mSofiaRef;
	nta_outgoing_t *mOutgoing;
	std::string mBranchId;
	SofiaAutoHome mHome;
	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value,
					  ...);
	void destroy();
	static int _callback(nta_outgoing_magic_t *magic, nta_outgoing_t *irq, const sip_t *sip);
};

class IncomingTransaction : public Transaction,
							public IncomingAgent,
							public std::enable_shared_from_this<IncomingTransaction> {
  public:
	// the use of make_shared() requires the constructor to be public, but don't use it. Use
	// RequestSipEvent::createIncomingTransaction().
	IncomingTransaction(Agent *agent);
	void handle(const std::shared_ptr<MsgSip> &ms);
	std::shared_ptr<MsgSip> createResponse(int status, char const *phrase);
	std::shared_ptr<MsgSip> getLastResponse();
	~IncomingTransaction();
	inline virtual Agent *getAgent() {
		return Transaction::getAgent();
	}
	/// The outgoing transaction that was eventually created to forward the message through a RequestSipEvent.
	std::shared_ptr<OutgoingTransaction> mOutgoing;

  private:
	friend class RequestSipEvent;
	static std::shared_ptr<IncomingTransaction> create(Agent *agent);

	std::shared_ptr<IncomingTransaction> mSofiaRef;
	nta_incoming_t *mIncoming;

	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value,
					  ...);
	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag,
					   tag_value_t value, ...);

	void destroy();
	static int _callback(nta_incoming_magic_t *magic, nta_incoming_t *irq, const sip_t *sip);
};

}