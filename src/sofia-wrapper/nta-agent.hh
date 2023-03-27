/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023  Belledonne Communications SARL, All rights reserved.

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

#include <map>
#include <sstream>
#include <type_traits>

#include <sofia-sip/nta.h>

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "nta-outgoing-transaction.hh"
#include "sofia-wrapper/utilities.hh"

namespace sofiasip {

/**
 * NtaAgent instances are in charge of listening the network and notify the upper code layer when an incoming
 * SIP message is received. It is also the entry point when the upper code layer need to send SIP messages on
 * the network or reply to SIP requests.
 *
 * Use createOutgoingTransaction() to send a request to another SIP agent.
 */
class NtaAgent {
public:
	/**
	 * Instantiate an NtaAgent.
	 * @param root The event loop that will be use to treat incoming network events.
	 * @param contactURI The default contact URI to use when sending SIP requests. This parameter
	 * is used to define which local address and port the agent will listen on.
	 */
	template <typename UriT>
	NtaAgent(const std::shared_ptr<SuRoot>& root, const UriT& contactURI) : mRoot{root} {
		auto* nativeContactURI = toSofiaSipUrlUnion(contactURI);
		mNativePtr = nta_agent_create(mRoot->getCPtr(), nativeContactURI, nullptr, nullptr, TAG_END());
		if (mNativePtr == nullptr) {
			throw std::runtime_error{"creating nta_agent_t failed"};
		}
	}
	NtaAgent(const NtaAgent&) = delete;
	NtaAgent(NtaAgent&&) = delete;
	~NtaAgent() {
		nta_agent_destroy(mNativePtr);
	}

	/**
	 * Send a SIP request and create an outgoing transaction to handle the response.
	 * The NtaAgent will keep a shared pointer on the transaction until it received a final response
	 * for this transaction.
	 * @param msg The SIP request to send.
	 * @return A pointer to the freshly created outgoing transaction.
	 */
	std::shared_ptr<NtaOutgoingTransaction> createOutgoingTransaction(std::unique_ptr<MsgSip>&& msg) {
		return createOutgoingTransaction(std::move(msg), nullptr);
	}
	template <typename UriT>
	std::shared_ptr<NtaOutgoingTransaction> createOutgoingTransaction(std::unique_ptr<MsgSip> msg,
	                                                                  const UriT& routeURI) {
		auto* nativeOutgoingTr = nta_outgoing_mcreate(
		    mNativePtr,
		    [](auto* magic, auto* tr, auto* sip) {
			    reinterpret_cast<NtaAgent*>(magic)->onOutgoingTransactionResponse(tr, sip);
			    return 0;
		    },
		    reinterpret_cast<nta_outgoing_magic_t*>(this), toSofiaSipUrlUnion(routeURI), msg->getMsg(), TAG_END());
		if (nativeOutgoingTr == nullptr) {
			throw std::runtime_error{"creating nta_outgoing_t failed"};
		}
		// increment the ref counter to avoid the C msg_t be destroyed when msgKeeper is destroyed.
		msg_ref(msg->getMsg());
		auto transaction = std::shared_ptr<NtaOutgoingTransaction>{new NtaOutgoingTransaction{nativeOutgoingTr}};
		auto& transactionHolder = mTransactions[nativeOutgoingTr];
		if (transactionHolder) {
			std::ostringstream err{};
			err << "C outgoing transaction[" << nativeOutgoingTr << "] already associated to C++ transaction["
			    << transactionHolder << "]";
			throw std::runtime_error{err.str()};
		}
		transactionHolder = transaction;
		return transaction;
	}

private:
	// Private methods
	void onOutgoingTransactionResponse(nta_outgoing_t* transaction, const sip_t* response) noexcept {
		auto it = mTransactions.find(transaction);
		if (it == mTransactions.end()) {
			SLOGE << "NtaAgent::onOutgoingTransactionResponse(transaction=" << transaction
			      << "): no C++ transaction associated";
			return;
		}
		if (response == nullptr || response->sip_status->st_status >= 200) {
			mTransactions.erase(it);
		}
	}

	// Private attributes
	nta_agent_t* mNativePtr{nullptr};
	std::shared_ptr<SuRoot> mRoot{nullptr};
	std::map<nta_outgoing_t*, std::shared_ptr<NtaOutgoingTransaction>> mTransactions{};
};
}; // namespace sofiasip
