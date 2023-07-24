/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "outgoing-transaction.hh"

#include <sofia-sip/su_md5.h>
#include <sofia-sip/su_random.h>
#include <sofia-sip/su_tagarg.h>

#include "flexisip/logmanager.hh"

#include "agent.hh"

using namespace flexisip;
using namespace std;

OutgoingTransaction::OutgoingTransaction(std::weak_ptr<Agent> agent)
    : Transaction{std::move(agent)}, mBranchId{getRandomBranch()} {
	LOGD("New OutgoingTransaction %p", this);
}

OutgoingTransaction::~OutgoingTransaction() {
	LOGD("Delete OutgoingTransaction %p", this);
	auto outgoing = mOutgoing.take();
	auto sharedAgent = mAgent.lock();
	if (outgoing && sharedAgent &&
	    !sharedAgent->mTerminating /* Transaction is already freed by sofia when agent is terminating */) {
		nta_outgoing_destroy(outgoing);
	}
}

string OutgoingTransaction::getRandomBranch() {
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	char branch[(SU_MD5_DIGEST_SIZE * 8 + 4) / 5 + 1];

	su_randmem(digest, sizeof(digest));

	msg_random_token(branch, sizeof(branch) - 1, digest, sizeof(digest));

	return branch;
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
	if (mOutgoing == nullptr) {
		LOGE("OutgoingTransaction::getRequestUri(): transaction not started !");
		return nullptr;
	}
	return nta_outgoing_request_uri(mOutgoing);
}

int OutgoingTransaction::getResponseCode() const {
	if (mOutgoing == nullptr) {
		LOGE("OutgoingTransaction::getResponseCode(): transaction not started !");
		return 0;
	}
	return nta_outgoing_status(mOutgoing);
}

shared_ptr<MsgSip> OutgoingTransaction::getRequestMsg() {
	if (mOutgoing == nullptr) {
		LOGE("OutgoingTransaction::getRequestMsg(): transaction not started !");
		return nullptr;
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
		mOutgoing = ownership::owned(nta_outgoing_mcreate(mAgent.lock()->mAgent, OutgoingTransaction::_callback,
		                                                  reinterpret_cast<nta_outgoing_magic_t*>(this), u, msg,
		                                                  ta_tags(ta), TAG_END()));
		nta_outgoing_add_custom_deinit(mOutgoing.borrow(), OutgoingTransaction::_customDeinit,
		                               reinterpret_cast<nta_outgoing_magic_t*>(this));
		ta_end(ta);
		if (mOutgoing == nullptr) {
			/*when nta_outgoing_mcreate() fails, we must destroy the message because it won't take the reference*/
			LOGE("Error during outgoing transaction creation");
			msg_destroy(msg);
		} else {
			mSofiaRef = shared_from_this();
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

int OutgoingTransaction::_callback(nta_outgoing_magic_t* magic, nta_outgoing_t*, const sip_t* sip) noexcept {
	OutgoingTransaction* otr = reinterpret_cast<OutgoingTransaction*>(magic);
	LOGD("OutgoingTransaction[%p] : _callback", otr);
	if (sip != nullptr) {
		auto outgoingAgent = dynamic_pointer_cast<OutgoingAgent>(otr->shared_from_this());
		auto msgSip = make_shared<MsgSip>(ownership::owned(nta_outgoing_getresponse(otr->mOutgoing.borrow())));
		auto sipEvent = make_shared<ResponseSipEvent>(outgoingAgent, msgSip,
		                                              otr->mAgent.lock()->getIncomingTport(msgSip->getMsg()));

		otr->mAgent.lock()->sendResponseEvent(sipEvent);

		if (sip->sip_status && sip->sip_status->st_status >= 200) {
			otr->queueFree();
		}
	} else {
		otr->queueFree();
	}
	return 0;
}

void OutgoingTransaction::_customDeinit(nta_outgoing_t* outgoing, nta_outgoing_magic_t* magic) noexcept {
	auto* ot = reinterpret_cast<OutgoingTransaction*>(magic);
	if (ot->mOutgoing.borrow() == outgoing && ot->mSofiaRef) {
		ot->mOutgoing.take();
		ot->mSofiaRef.reset();
	}
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
	mAgent.lock()->getRoot()->addToMainLoop([self = std::move(mSofiaRef)] {});
	if (mOutgoing) {
		// avoid callbacks
		nta_outgoing_remove_custom_deinit(mOutgoing.borrow());
		nta_outgoing_bind(mOutgoing.borrow(), nullptr, nullptr);
	}
}
