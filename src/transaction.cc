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

#include "transaction.hh"

#include <algorithm>

#include <memory>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/su_random.h>
#include <sofia-sip/su_tagarg.h>

#include <bctoolbox/ownership.hh>

#include "flexisip/common.hh"
#include "flexisip/event.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/branch-info.hh"

using namespace std;

namespace flexisip {

Transaction::Property Transaction::_getProperty(const std::string& name) const noexcept {
	auto it = mProperties.find(name);
	if (it != mProperties.cend()) {
		return it->second;
	} else {
		auto wit = mWeakProperties.find(name);
		if (wit == mWeakProperties.cend()) return Property{};
		const auto& prop = wit->second;
		return Property{prop.value.lock(), prop.type};
	}
}

static string getRandomBranch() {
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	char branch[(SU_MD5_DIGEST_SIZE * 8 + 4) / 5 + 1];

	su_randmem(digest, sizeof(digest));

	msg_random_token(branch, sizeof(branch) - 1, digest, sizeof(digest));

	return branch;
}
std::vector<std::weak_ptr<IncomingTransaction>> IncomingTransaction::sNaughtyList{};
std::shared_ptr<IncomingTransaction> IncomingTransaction::makeShared(Agent* agent) {
	std::shared_ptr<IncomingTransaction> instance{new IncomingTransaction(agent)};
	for (auto& weak : sNaughtyList) {
		if (weak.expired()) {
			SLOGD << "IncomingTransaction memory tracker - Free slot found, overwriting (at: " << std::addressof(weak)
			      << ")";
			weak = instance;
			return instance;
		}
	}

	sNaughtyList.emplace_back(instance);
	return instance;
}
void IncomingTransaction::vacuum() {
	for (const auto& weak : sNaughtyList) {
		if (auto strong = weak.lock()) {
			strong->mSofiaRef.reset();
		}
	}
	sNaughtyList.clear();
}

OutgoingTransaction::OutgoingTransaction(Agent* agent) : Transaction{agent}, mBranchId{getRandomBranch()} {
	LOGD("New OutgoingTransaction %p", this);
}

OutgoingTransaction::~OutgoingTransaction() {
	LOGD("Delete OutgoingTransaction %p", this);
	auto outgoing = mOutgoing.take();
	if (outgoing && !mAgent->mTerminating /* Transaction is already freed by sofia when agent is terminating */) {
		nta_outgoing_destroy(outgoing);
	}
}

const string& OutgoingTransaction::getBranchId() const {
	return mBranchId;
}
su_home_t* OutgoingTransaction::getHome() {
	return mHome.home();
}

template <typename... Tags>
void OutgoingTransaction::_cancel(Tags... tags) {
	if (mOutgoing) {
		// NTATAG_CANCEL_2543(1) --> the stack generates a 487 response to the request internally
		nta_outgoing_tcancel(mOutgoing.borrow(), nullptr, nullptr, tags..., NTATAG_CANCEL_2543(1), TAG_END());
	} else {
		LOGE("OutgoingTransaction::cancel(): transaction already destroyed.");
	}
}

void OutgoingTransaction::cancel() {
	_cancel();
}

void OutgoingTransaction::cancelWithReason(sip_reason_t* reason) {
	_cancel(SIPTAG_REASON(reason));
}

const url_t* OutgoingTransaction::getRequestUri() const {
	if (mOutgoing == NULL) {
		LOGE("OutgoingTransaction::getRequestUri(): transaction not started !");
		return NULL;
	}
	return nta_outgoing_request_uri(mOutgoing);
}

int OutgoingTransaction::getResponseCode() const {
	if (mOutgoing == NULL) {
		LOGE("OutgoingTransaction::getResponseCode(): transaction not started !");
		return 0;
	}
	return nta_outgoing_status(mOutgoing);
}

shared_ptr<MsgSip> OutgoingTransaction::getRequestMsg() {
	if (mOutgoing == NULL) {
		LOGE("OutgoingTransaction::getRequestMsg(): transaction not started !");
		return NULL;
	}

	return make_shared<MsgSip>(ownership::owned(nta_outgoing_getrequest(mOutgoing.borrow())));
}

void OutgoingTransaction::send(
    const shared_ptr<MsgSip>& ms, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;

	LOGD("Message is sent through an outgoing transaction.");

	if (!mOutgoing) {
		msg_t* msg = msg_ref_create(ms->getMsg());
		ta_start(ta, tag, value);
		mOutgoing = ownership::owned(nta_outgoing_mcreate(mAgent->mAgent, OutgoingTransaction::_callback,
		                                                  (nta_outgoing_magic_t*)this, u, msg, ta_tags(ta), TAG_END()));
		ta_end(ta);
		if (mOutgoing == NULL) {
			/*when nta_outgoing_mcreate() fails, we must destroy the message because it won't take the reference*/
			LOGE("Error during outgoing transaction creation");
			msg_destroy(msg);
		} else {
			mSelfRef = shared_from_this();
		}
	} else {
		// sofia transaction already created, this happens when attempting to forward a cancel
		const auto* sip = ms->getSip();
		if (sip->sip_request->rq_method == sip_method_cancel) {
			cancelWithReason(sip->sip_reason);
		} else {
			LOGE("Attempting to send request %s through an already created outgoing transaction.",
			     sip->sip_request->rq_method_name);
		}
	}
}

int OutgoingTransaction::_callback(nta_outgoing_magic_t* magic, nta_outgoing_t*, const sip_t* sip) {
	OutgoingTransaction* otr = reinterpret_cast<OutgoingTransaction*>(magic);
	LOGD("OutgoingTransaction callback %p", otr);
	if (sip != NULL) {
		auto oagent = dynamic_pointer_cast<OutgoingAgent>(otr->shared_from_this());
		auto msgsip = make_shared<MsgSip>(ownership::owned(nta_outgoing_getresponse(otr->mOutgoing.borrow())));
		shared_ptr<ResponseSipEvent> sipevent =
		    make_shared<ResponseSipEvent>(oagent, msgsip, otr->mAgent->getIncomingTport(msgsip->getMsg()));

		otr->mAgent->sendResponseEvent(sipevent);

		if (sip->sip_status && sip->sip_status->st_status >= 200) {
			otr->queueFree();
		}
	} else {
		otr->queueFree();
	}
	return 0;
}

void OutgoingTransaction::queueFree() {
	/* Postpone the destruction of sofia sip outgoing transaction.
	   The cancellation of an INVITE transaction may result in the transaction callback
	   being invoked, which results in the transaction being destroyed immediately while still doing processing with
	   the creation of the cancel transaction. The exact case would be that the sending of the CANCEL generates a
	   transport error that is immediately notified to the INVITE transaction (because the CANCEL and the INVITE use
	   the same transport) with an internal 503 response, which goes to flexisip, and would reset mSelfRef, which would
	   call nta_outgoing_destroy(). nta_outgoing_tcancel() is then left with the INVITE transaction freed (full of
	   0xaaaaaaaa), which crashes.
	*/
	mAgent->getRoot()->addToMainLoop([self = std::move(mSelfRef)] {});
	mIncoming.reset();
	if (mOutgoing) {
		nta_outgoing_bind(mOutgoing.borrow(), NULL, NULL); // avoid callbacks
	}
}

IncomingTransaction::IncomingTransaction(Agent* agent) : Transaction(agent) {
	LOGD("New IncomingTransaction %p", this);
}

void IncomingTransaction::handle(const shared_ptr<MsgSip>& ms) {
	msg_t* msg = ms->getMsg();
	msg = msg_ref_create(msg);
	mIncoming = nta_incoming_create(mAgent->mAgent, NULL, msg, sip_object(msg), TAG_END());
	if (mIncoming != NULL) {
		nta_incoming_bind(mIncoming, IncomingTransaction::_callback, (nta_incoming_magic_t*)this);
		mSofiaRef = shared_from_this();
	} else {
		LOGE("Error during incoming transaction creation");
	}
}

IncomingTransaction::~IncomingTransaction() {
	LOGD("Delete IncomingTransaction %p", this);
}

shared_ptr<MsgSip> IncomingTransaction::createResponse(int status, char const* phrase) {
	if (mIncoming) {
		auto msg = ownership::owned(nta_incoming_create_response(mIncoming, status, phrase));
		if (!msg) {
			LOGE("IncomingTransaction::createResponse(): this=%p cannot create response.", this);
			return shared_ptr<MsgSip>();
		}

		return make_shared<MsgSip>(std::move(msg));
	}
	LOGE("IncomingTransaction::createResponse(): this=%p transaction is finished, cannot create response.", this);
	return shared_ptr<MsgSip>();
}

void IncomingTransaction::send(const shared_ptr<MsgSip>& ms, url_string_t const*, tag_type_t, tag_value_t, ...) {
	if (mIncoming) {
		msg_t* msg =
		    msg_ref_create(ms->getMsg()); // need to increment refcount of the message because mreply will decrement it.
		LOGD("Response is sent through an incoming transaction.");
		nta_incoming_mreply(mIncoming, msg);
		if (ms->getSip()->sip_status != NULL && ms->getSip()->sip_status->st_status >= 200) {
			destroy();
		}
	} else {
		LOGW("Invalid incoming");
	}
}

void IncomingTransaction::reply(
    const shared_ptr<MsgSip>&, int status, char const* phrase, tag_type_t tag, tag_value_t value, ...) {
	if (mIncoming) {
		mAgent->incrReplyStat(status);
		ta_list ta;
		ta_start(ta, tag, value);
		nta_incoming_treply(mIncoming, status, phrase, ta_tags(ta));
		ta_end(ta);
		if (status >= 200) {
			destroy();
		}
	} else {
		LOGW("Invalid incoming");
	}
}

int IncomingTransaction::_callback(nta_incoming_magic_t* magic, nta_incoming_t*, const sip_t* sip) {
	IncomingTransaction* it = reinterpret_cast<IncomingTransaction*>(magic);
	LOGD("IncomingTransaction callback %p", it);
	if (sip != NULL) {
		auto ev = make_shared<RequestSipEvent>(
		    it->shared_from_this(),
		    make_shared<MsgSip>(ownership::owned(nta_incoming_getrequest_ackcancel(it->mIncoming))));
		it->mAgent->sendRequestEvent(ev);
	} else {
		it->destroy();
	}
	return 0;
}

shared_ptr<MsgSip> IncomingTransaction::getLastResponse() {
	auto msg = ownership::owned(nta_incoming_getresponse(mIncoming));
	if (!msg) {
		return shared_ptr<MsgSip>();
	}

	return make_shared<MsgSip>(std::move(msg));
}

void IncomingTransaction::destroy() {
	if (mSofiaRef) {
		nta_incoming_bind(mIncoming, NULL, NULL); // avoid callbacks
		nta_incoming_destroy(mIncoming);
		mIncoming = nullptr;
		mOutgoing.reset();
		mSofiaRef.reset(); // This MUST be the last instruction of this function, because it may destroy the
		                   // IncomingTransaction.
	}
}

} // namespace flexisip
