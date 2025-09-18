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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <map>
#include <sstream>
#include <string_view>
#include <type_traits>

#include <sofia-sip/nta.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport.h>

#include "flexisip/flexisip-exception.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "nta-outgoing-transaction.hh"
#include "sofia-wrapper/utilities.hh"

namespace sofiasip {

/**
 * NtaAgent instances are in charge of listening the network and notify the upper code layer when an incoming
 * SIP message is received. It is also the entry point when the upper code layer needs to send SIP messages on
 * the network or reply to SIP requests.
 *
 * Use createOutgoingTransaction() to send a request to another SIP agent.
 */
class NtaAgent {
public:
	/**
	 * Instantiate an NtaAgent.
	 *
	 * @param root          the event loop that will be used to process incoming network events.
	 * @param contactURI    the default contact URI to use when sending SIP requests. This parameter
	 * is used to define which local address and port the agent will listen on.
	 * @param callback      function called when a new SIP message is received
	 * @param magic         user data which are then reachable from the callback function
	 * @param tags          NTA tagged arguments (no need to add TAG_END())
	 *
	 * @throw std::runtime_error on agent creation failure
	 */
	template <typename UriT, typename... Tags>
	NtaAgent(const std::shared_ptr<SuRoot>& root,
	         const UriT& contactURI,
	         nta_message_f* callback = nullptr,
	         nta_agent_magic_t* magic = nullptr,
	         Tags&&... tags)
	    : mRoot{root} {
		const url_string_t* contactUrl = nullptr;
		if constexpr (std::is_same_v<UriT, const url_string_t*>) {
			contactUrl = contactURI;
		} else {
			contactUrl = toSofiaSipUrlUnion(contactURI);
		}
		mNativePtr =
		    nta_agent_create(mRoot->getCPtr(), contactUrl, callback, magic, std::forward<Tags>(tags)..., TAG_END());
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
	 * The NtaAgent will keep a shared pointer on the transaction until it received a final response for this
	 * transaction.
	 *
	 * @param msg   the SIP request to send
	 *
	 * @return      a pointer to the freshly created outgoing transaction
	 */
	std::shared_ptr<NtaOutgoingTransaction> createOutgoingTransaction(std::unique_ptr<MsgSip>&& msg) {
		return createOutgoingTransaction(std::move(msg), nullptr);
	}

	template <typename UriT>
	std::shared_ptr<NtaOutgoingTransaction> createOutgoingTransaction(std::string_view rawMsg, const UriT& routeURI) {
		return createOutgoingTransaction(std::make_unique<MsgSip>(0, rawMsg), routeURI);
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
		// Increment the ref counter to avoid the C msg_t be destroyed when msgKeeper is destroyed.
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

	/**
	 * Add a transport to the agent.
	 * Creates a new transport and binds it to the port specified by the uri.
	 *
	 * @param uri     tport uri
	 * @param tags    NTA tagged arguments (no need to add TAG_END())
	 *
	 * @return        0 on success and -1 otherwise with errno being set appropriately
	 */
	template <typename UriT, typename... Tags>
	int addTransport(const UriT& uri, Tags&&... tags) {
		return nta_agent_add_tport(mNativePtr, toSofiaSipUrlUnion(uri), std::forward<Tags>(tags)..., TAG_END());
	}

	/**
	 * Return the first port on which the agent is listening.
	 * May return empty string if master transport does not exist.
	 */
	const char* getFirstPort() const {
		const auto firstTransport = ::tport_primaries(::nta_agent_tports(mNativePtr));
		return firstTransport ? ::tport_name(firstTransport)->tpn_port : "";
	}

	/*
	 * Return the master transport for the agent.
	 */
	const tport_t* getTransports() const {
		return ::nta_agent_tports(mNativePtr);
	}

	/*
	 * Return the sofia agent.
	 */
	nta_agent_t* getAgent() {
		return mNativePtr;
	}

private:
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

	nta_agent_t* mNativePtr{nullptr};
	std::shared_ptr<SuRoot> mRoot{nullptr};
	std::map<nta_outgoing_t*, std::shared_ptr<NtaOutgoingTransaction>> mTransactions{};
};

}; // namespace sofiasip