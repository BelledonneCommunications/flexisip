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

#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include <sofia-sip/msg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/nta.h>

#include <flexisip/event.hh>
#include <flexisip/sofia-wrapper/home.hh>

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
	public:
		Transaction(Agent *agent) noexcept : mAgent{agent} {}
		Transaction(const Transaction &) = delete;
		Transaction(Transaction &&) = delete;
		~Transaction() = default;

		Agent *getAgent() const noexcept {return mAgent;}

		template <typename T, typename StrT> void setProperty(StrT &&name, const std::shared_ptr<T> &value) noexcept {
			auto typeName = typeid(T).name();
			mWeakProperties.erase(name); // ensures the property value isn't in the two lists both.
			mProperties[std::forward<StrT>(name)] = Property{value, typeName};
		}

		template <typename T, typename StrT> void setProperty(StrT &&name, const std::weak_ptr<T> &value) noexcept {
			auto typeName = typeid(T).name();
			mProperties.erase(name); // ensures the property value isn't in the two lists both.
			mWeakProperties[std::forward<StrT>(name)] = WProperty{value, typeName};
		}

		template <typename T> std::shared_ptr<T> getProperty(const std::string &name) const {
			auto prop = _getProperty(name);
			if (prop.value == nullptr) return nullptr;
			if (std::strcmp(prop.type, typeid(T).name()) != 0) {throw std::bad_cast{};}
			return std::static_pointer_cast<T>(prop.value);
		}

		void removeProperty(const std::string &name) noexcept {
			mProperties.erase(name);
			mWeakProperties.erase(name);
		}

	protected:
		struct Property {
			Property() noexcept = default;
			template <typename PtrT>
			Property(PtrT &&value, const char *type) noexcept : value{std::forward<PtrT>(value)}, type{type} {}

			std::shared_ptr<void> value{};
			const char *type{nullptr};
		};
		struct WProperty {
			WProperty() noexcept = default;
			template <typename PtrT>
			WProperty(PtrT &&value, const char *type) noexcept : value{std::forward<PtrT>(value)}, type{type} {}

			std::weak_ptr<void> value{};
			const char *type{nullptr};
		};

		Property _getProperty(const std::string &name) const noexcept;

		void looseProperties() noexcept {
			mProperties.clear();
			mWeakProperties.clear();
		}

		Agent *mAgent{nullptr};
		std::unordered_map<std::string, Property> mProperties{};
		std::unordered_map<std::string, WProperty> mWeakProperties{};
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

	virtual Agent *getAgent() {return Transaction::getAgent();}
	/// The incoming transaction from which the message comes from, if any.
	std::weak_ptr<IncomingTransaction> mIncoming;
  private:
	friend class RequestSipEvent;

	std::shared_ptr<OutgoingTransaction> mSofiaRef;
	nta_outgoing_t *mOutgoing;
	std::string mBranchId;
	sofiasip::Home mHome;
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
	std::weak_ptr<OutgoingTransaction> mOutgoing;

  private:
	friend class RequestSipEvent;

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
