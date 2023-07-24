/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/sip.h>

#include <bctoolbox/ownership.hh>

#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/home.hh"

using namespace ownership;

namespace flexisip {

class OutgoingTransaction;
class IncomingTransaction;
class Agent;
class BranchInfo;

class IncomingAgent {
public:
	IncomingAgent() = default;
	IncomingAgent(const IncomingAgent&) = delete;
	virtual ~IncomingAgent() = default;

	virtual void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual void reply(
	    const std::shared_ptr<MsgSip>& msg, int status, char const* phrase, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual std::weak_ptr<Agent> getAgent() = 0;
};

class OutgoingAgent {
public:
	OutgoingAgent() = default;
	OutgoingAgent(const OutgoingAgent&) = delete;
	virtual ~OutgoingAgent() = default;

	virtual void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) = 0;
	virtual std::weak_ptr<Agent> getAgent() = 0;
};

class Transaction {
public:
	Transaction(std::weak_ptr<Agent> agent) noexcept : mAgent{agent} {
	}
	Transaction(const Transaction&) = delete;
	virtual ~Transaction() = default;

	std::weak_ptr<Agent> getAgent() const noexcept {
		return mAgent;
	}

	template <typename T, typename StrT>
	void setProperty(StrT&& name, const std::shared_ptr<T>& value) noexcept {
		auto typeName = typeid(T).name();
		mWeakProperties.erase(name); // ensures the property value isn't in the two lists both.
		mProperties[std::forward<StrT>(name)] = Property{value, typeName};
	}

	template <typename T, typename StrT>
	void setProperty(StrT&& name, const std::weak_ptr<T>& value) noexcept {
		auto typeName = typeid(T).name();
		mProperties.erase(name); // ensures the property value isn't in the two lists both.
		mWeakProperties[std::forward<StrT>(name)] = WProperty{value, typeName};
	}

	template <typename T>
	std::shared_ptr<T> getProperty(const std::string& name) const {
		auto prop = _getProperty(name);
		if (prop.value == nullptr) return nullptr;
		if (std::strcmp(prop.type, typeid(T).name()) != 0) {
			throw std::bad_cast{};
		}
		return std::static_pointer_cast<T>(prop.value);
	}

	void removeProperty(const std::string& name) noexcept {
		mProperties.erase(name);
		mWeakProperties.erase(name);
	}

protected:
	struct Property {
		Property() = default;
		template <typename PtrT>
		Property(PtrT&& value, const char* type) noexcept : value{std::forward<PtrT>(value)}, type{type} {
		}

		std::shared_ptr<void> value{};
		const char* type{nullptr};
	};
	struct WProperty {
		WProperty() = default;
		template <typename PtrT>
		WProperty(PtrT&& value, const char* type) noexcept : value{std::forward<PtrT>(value)}, type{type} {
		}

		std::weak_ptr<void> value{};
		const char* type{nullptr};
	};

	Property _getProperty(const std::string& name) const noexcept;

	void looseProperties() noexcept {
		mProperties.clear();
		mWeakProperties.clear();
	}

	std::weak_ptr<Agent> mAgent = std::weak_ptr<Agent>{};
	std::unordered_map<std::string, Property> mProperties{};
	std::unordered_map<std::string, WProperty> mWeakProperties{};
};

class OutgoingTransaction : public Transaction,
                            public OutgoingAgent,
                            public std::enable_shared_from_this<OutgoingTransaction> {
public:
	// the use of make_shared() requires the constructor to be public, but don't use it. Use
	// RequestSipEvent::createOutgoingTransaction().
	OutgoingTransaction(std::weak_ptr<Agent> agent);
	~OutgoingTransaction();

	std::weak_ptr<Agent> getAgent() override {
		return Transaction::getAgent();
	}

	std::shared_ptr<IncomingTransaction> getIncomingTransaction() const noexcept {
		return mIncoming.lock();
	}

	const url_t* getRequestUri() const;
	const std::string& getBranchId() const;
	su_home_t* getHome();
	int getResponseCode() const;
	std::shared_ptr<MsgSip> getRequestMsg();

	void cancel();
	void cancelWithReason(sip_reason_t* reason);

private:
	void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) override;
	/* Break self-reference on the next main loop iteration */
	void queueFree();

	static int _callback(nta_outgoing_magic_t* magic, nta_outgoing_t* irq, const sip_t* sip);

	template <typename... Tags>
	void _cancel(Tags... tags);

	sofiasip::Home mHome{};
	Owned<nta_outgoing_t> mOutgoing{nullptr};
	std::shared_ptr<OutgoingTransaction> mSelfRef{};
	std::string mBranchId{};
	std::weak_ptr<IncomingTransaction> mIncoming; // The incoming transaction from which the message comes from, if any.

	friend class RequestSipEvent;
};

class IncomingTransaction : public Transaction,
                            public IncomingAgent,
                            public std::enable_shared_from_this<IncomingTransaction> {
public:
	// the use of make_shared() requires the constructor to be public, but don't use it. Use
	// RequestSipEvent::createIncomingTransaction().
	IncomingTransaction(std::weak_ptr<Agent> agent);
	~IncomingTransaction() override;

	std::weak_ptr<Agent> getAgent() override {
		return Transaction::getAgent();
	}

	std::shared_ptr<OutgoingTransaction> getOutgoingTransaction() const noexcept {
		return mOutgoing.lock();
	}

	void handle(const std::shared_ptr<MsgSip>& ms);
	std::shared_ptr<MsgSip> createResponse(int status, char const* phrase);
	std::shared_ptr<MsgSip> getLastResponse();

private:
	void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) override;
	void reply(const std::shared_ptr<MsgSip>& msg,
	           int status,
	           char const* phrase,
	           tag_type_t tag,
	           tag_value_t value,
	           ...) override;
	void destroy();

	static int _callback(nta_incoming_magic_t* magic, nta_incoming_t* irq, const sip_t* sip);

	nta_incoming_t* mIncoming{nullptr};
	std::weak_ptr<OutgoingTransaction> mOutgoing{}; /* The outgoing transaction that was eventually created to forward
	                                                 the message through a RequestSipEvent. */
	std::shared_ptr<IncomingTransaction> mSofiaRef{};

	friend class RequestSipEvent;
};

} // namespace flexisip
