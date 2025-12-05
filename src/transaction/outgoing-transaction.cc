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

#include "outgoing-transaction.hh"

#include "sofia-sip/nta_tport.h"
#include "sofia-sip/su_md5.h"
#include "sofia-sip/su_random.h"
#include "sofia-sip/su_tagarg.h"

#include "agent.hh"
#include "flexisip/logmanager.hh"

using namespace flexisip;
using namespace std;

namespace {

string getRandomBranch() {
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	char branch[(SU_MD5_DIGEST_SIZE * 8 + 4) / 5 + 1];

	su_randmem(digest, sizeof(digest));
	msg_random_token(branch, sizeof(branch) - 1, digest, sizeof(digest));

	return branch;
}

} // namespace

OutgoingTransaction::OutgoingTransaction(std::weak_ptr<Agent> agent)
    : Transaction{std::move(agent)}, mBranchId{getRandomBranch()},
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "OutgoingTransaction")) {
	LOGD << "New instance";
}

OutgoingTransaction::~OutgoingTransaction() {
	LOGD << "Delete instance";
	auto* outgoing = mOutgoing.take();
	// Sofia-sip has already freed the transaction when the agent is terminating.
	if (const auto agent = mAgent.lock(); agent && outgoing && !agent->mTerminating) nta_outgoing_destroy(outgoing);
}

int OutgoingTransaction::getResponseCode() const {
	if (mOutgoing == nullptr) {
		LOGE << "Transaction not started";
		return 0;
	}
	return nta_outgoing_status(mOutgoing);
}

const url_t* OutgoingTransaction::getRequestUri() const {
	if (mOutgoing == nullptr) {
		LOGE << "Transaction not started";
		return nullptr;
	}
	return nta_outgoing_request_uri(mOutgoing);
}

shared_ptr<MsgSip> OutgoingTransaction::getRequestMsg() {
	if (mOutgoing == nullptr) {
		LOGE << "Transaction not started";
		return nullptr;
	}
	return make_shared<MsgSip>(owned(nta_outgoing_getrequest(mOutgoing.borrow())));
}

void OutgoingTransaction::cancel() {
	cancel<>();
}

void OutgoingTransaction::cancelWithReason(const sip_reason_t* reason) {
	cancel(SIPTAG_REASON(reason));
}

int OutgoingTransaction::responseCallback(nta_outgoing_magic_t* magic, nta_outgoing_t*, const sip_t* sip) noexcept {
	auto* otr = reinterpret_cast<OutgoingTransaction*>(magic);
	LOGD_CTX(otr->mLogPrefix) << "Processing response";

	if (sip == nullptr) {
		otr->queueFree();
		return 0;
	}

	auto msgSip = make_shared<MsgSip>(owned(nta_outgoing_getresponse(otr->mOutgoing.borrow())));
	if (const auto agent = otr->mAgent.lock()) {
		auto* transport = agent->getIncomingTport(msgSip->getMsg());
		agent->processResponse(make_unique<ResponseSipEvent>(otr->shared_from_this(), msgSip, transport));
	} else {
		LOGD_CTX(otr->mLogPrefix) << "Failed to process the response: Agent has been destroyed";
		return 1;
	}

	if (sip->sip_status && sip->sip_status->st_status >= 200) otr->queueFree();

	return 0;
}

void OutgoingTransaction::deinitializationCallback(nta_outgoing_t* outgoing, nta_outgoing_magic_t* magic) noexcept {
	if (auto* ot = reinterpret_cast<OutgoingTransaction*>(magic); ot->mSofiaRef && ot->mOutgoing.borrow() == outgoing) {
		ot->mOutgoing.take();
		ot->mSofiaRef.reset();
	}
}

void OutgoingTransaction::beforeSendCallback(nta_outgoing_t* orq, nta_outgoing_magic_t* magic) {
	auto* transaction = reinterpret_cast<OutgoingTransaction*>(magic);
	const auto msgSip = make_shared<MsgSip>(owned(nta_outgoing_getrequest(orq)));
	const auto* transport = tport_parent(nta_outgoing_transport(orq));

	for (const auto& callback : transaction->mBeforeSendCallbacks) {
		callback(msgSip, transport);
	}

	// Callback functions MUST be executed only once.
	transaction->mBeforeSendCallbacks.clear();
}

void OutgoingTransaction::send(const shared_ptr<MsgSip>& msg,
                               url_string_t const* u,
                               RequestSipEvent::BeforeSendCallbackList&& callbacks,
                               tag_type_t tag,
                               tag_value_t value,
                               ...) {
	LOGD << "Message is sent through an outgoing transaction";
	mBeforeSendCallbacks = std::move(callbacks);

	if (mOutgoing) {
		// Sofia transaction already created, this happens when attempting to forward a cancel.
		if (msg->getSipMethod() == sip_method_cancel) {
			cancelWithReason(msg->getSip()->sip_reason);
		} else {
			LOGE << "Attempting to send '" << msg->getSip()->sip_request->rq_method_name
			     << "' request through an already created outgoing transaction";
		}

		return;
	}

	ta_list ta;
	ta_start(ta, tag, value);

	auto* msgRef = msg_ref_create(msg->getMsg());
	auto* magic = reinterpret_cast<nta_outgoing_magic_t*>(this);
	const nta_outgoing_callbacks_t sofiaCallbacks = {
	    .response = responseCallback,
	    .response_magic = magic,
	    .custom_deinit = deinitializationCallback,
	    .custom_deinit_magic = magic,
	    .before_send = mBeforeSendCallbacks.empty() ? nullptr : beforeSendCallback,
	    .before_send_magic = mBeforeSendCallbacks.empty() ? nullptr : magic,
	};
	mOutgoing = owned(nta_outgoing_mcreate(mAgent.lock()->mAgent, sofiaCallbacks, u, msgRef, ta_tags(ta), TAG_END()));

	ta_end(ta);

	if (mOutgoing == nullptr) {
		// When nta_outgoing_mcreate() fails, we must destroy the message because it will not take the reference.
		LOGE << "Failed to create sofia-sip outgoing transaction: aborting";
		msg_destroy(msgRef);
		return;
	}

	mSofiaRef = shared_from_this();
}

void OutgoingTransaction::queueFree() {
	// Postpone the destruction of sofia sip outgoing transaction.
	// The cancellation of an 'INVITE' transaction may result in the transaction callback being invoked, which leads to
	// the transaction being destroyed immediately while still doing processing with the creation of the cancel
	// transaction. The exact case would be that the sending of the 'CANCEL' generates a transport error immediately
	// notified to the 'INVITE' transaction (because the 'CANCEL' and the 'INVITE' use the same transport) with an
	// internal 503 response, which goes to flexisip, and would reset mSelfRef, which would call nta_outgoing_destroy().
	// nta_outgoing_tcancel() is then left with the 'INVITE' transaction freed (full of 0xaaaaaaaa), which crashes.
	mAgent.lock()->getRoot()->addToMainLoop([self = std::move(mSofiaRef)] {});
	if (!mOutgoing) return;

	// Prevent later responses to trigger the callback.
	nta_outgoing_remove_custom_deinit(mOutgoing.borrow());
	nta_outgoing_bind(
	    mOutgoing.borrow(), [](nta_outgoing_magic_t*, nta_outgoing_t*, const sip_t*) { return 0; }, nullptr);
}

template <typename... Tags>
void OutgoingTransaction::cancel(Tags... tags) {
	if (!mOutgoing) {
		LOGD << "Transaction already destroyed";
		return;
	}

	nta_outgoing_tcancel(mOutgoing.borrow(), nullptr, nullptr, tags..., NTATAG_CANCEL_3261(1), TAG_END());
	// Prevent from calling the custom callback whenever a new response is being received for this outgoing
	// transaction. From now on, we want to let sofia-sip manage transaction's end of life.
	nta_outgoing_destroy(mOutgoing.borrow());
}