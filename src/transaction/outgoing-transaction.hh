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

#include <bctoolbox/ownership.hh>

#include "flexisip/event.hh"

#include "transaction/outgoing-agent.hh"
#include "transaction/transaction.hh"

namespace flexisip {

class OutgoingTransaction : public Transaction,
                            public OutgoingAgent,
                            public std::enable_shared_from_this<OutgoingTransaction> {
public:
	// the use of make_shared() requires the constructor to be public, but don't use it. Use
	// RequestSipEvent::createOutgoingTransaction().
	explicit OutgoingTransaction(std::weak_ptr<Agent> agent);
	~OutgoingTransaction() override;

	std::weak_ptr<Agent> getAgent() noexcept override {
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

	static int _callback(nta_outgoing_magic_t* magic, nta_outgoing_t* irq, const sip_t* sip) noexcept;
	static void _customDeinit(nta_outgoing_t* outgoing, nta_outgoing_magic_t* magic) noexcept;

	template <typename... Tags>
	void _cancel(Tags... tags);

	static std::string getRandomBranch();

	sofiasip::Home mHome{};
	Owned<nta_outgoing_t> mOutgoing{nullptr};
	std::shared_ptr<OutgoingTransaction> mSofiaRef{};
	std::string mBranchId{};
	std::weak_ptr<IncomingTransaction> mIncoming; // The incoming transaction from which the message comes from, if any.

	friend class RequestSipEvent;
};

} // namespace flexisip
