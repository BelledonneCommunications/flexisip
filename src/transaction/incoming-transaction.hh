/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <memory>
#include <string>
#include <unordered_map>

#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/home.hh"

#include "transaction/incoming-agent.hh"
#include "transaction/transaction.hh"

namespace flexisip {

class IncomingTransaction : public Transaction,
                            public IncomingAgent,
                            public std::enable_shared_from_this<IncomingTransaction> {
public:
	// the use of make_shared() requires the constructor to be public, but don't use it. Use
	// RequestSipEvent::createIncomingTransaction().
	IncomingTransaction(std::weak_ptr<Agent> agent);
	~IncomingTransaction() override;

	std::weak_ptr<Agent> getAgent() noexcept override {
		return Transaction::getAgent();
	}

	std::shared_ptr<OutgoingTransaction> getOutgoingTransaction() const noexcept {
		return mOutgoing.lock();
	}

	void handle(const std::shared_ptr<MsgSip>& ms);
	std::shared_ptr<MsgSip> createResponse(int status, char const* phrase);
	std::shared_ptr<MsgSip> getLastResponse();

private:
	IncomingTransaction(Agent* agent);

	void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) override;
	void reply(const std::shared_ptr<MsgSip>& msg,
	           int status,
	           char const* phrase,
	           tag_type_t tag,
	           tag_value_t value,
	           ...) override;
	void destroy();

	static int _callback(nta_incoming_magic_t* magic, nta_incoming_t* irq, const sip_t* sip) noexcept;
	static void _customDeinit(nta_incoming_t* incoming, nta_incoming_magic_t* magic) noexcept;

	nta_incoming_t* mIncoming{nullptr};
	std::weak_ptr<OutgoingTransaction> mOutgoing{}; /* The outgoing transaction that was eventually created to forward
	                                                 the message through a RequestSipEvent. */
	std::shared_ptr<IncomingTransaction> mSofiaRef{};

	friend class RequestSipEvent;
};

} // namespace flexisip
