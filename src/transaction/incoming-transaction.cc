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

#include "incoming-transaction.hh"

#include <sofia-sip/su_tagarg.h>

#include "flexisip/logmanager.hh"

#include "agent.hh"

using namespace flexisip;
using namespace std;

IncomingTransaction::IncomingTransaction(std::weak_ptr<Agent> agent) : Transaction(std::move(agent)) {
	LOGD("New IncomingTransaction %p", this);
}

IncomingTransaction::~IncomingTransaction() {
	LOGD("Delete IncomingTransaction %p", this);
}

void IncomingTransaction::_customDeinit(nta_incoming_t* incoming, nta_incoming_magic_t* magic) noexcept {
	auto* it = reinterpret_cast<IncomingTransaction*>(magic);
	if (it->mIncoming == incoming && it->mSofiaRef) {
		it->mIncoming = nullptr;
		it->mSofiaRef.reset();
	}
}

void IncomingTransaction::handle(const shared_ptr<MsgSip>& ms) {
	msg_t* msg = ms->getMsg();
	msg = msg_ref_create(msg);
	mIncoming = nta_incoming_create(mAgent.lock()->mAgent, nullptr, msg, sip_object(msg), TAG_END());
	if (mIncoming != nullptr) {
		nta_incoming_bind(mIncoming, IncomingTransaction::_callback, reinterpret_cast<nta_incoming_magic_t*>(this));
		nta_incoming_add_custom_deinit(mIncoming, IncomingTransaction::_customDeinit,
		                               reinterpret_cast<nta_incoming_magic_t*>(this));
		mSofiaRef = shared_from_this();
	} else {
		LOGE("Error during incoming transaction creation");
	}
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
		if (ms->getSip()->sip_status != nullptr && ms->getSip()->sip_status->st_status >= 200) {
			destroy();
		}
	} else {
		LOGW("Invalid incoming");
	}
}

void IncomingTransaction::reply(
    const shared_ptr<MsgSip>&, int status, char const* phrase, tag_type_t tag, tag_value_t value, ...) {
	if (mIncoming) {
		if (auto sharedAgent = mAgent.lock()) sharedAgent->incrReplyStat(status);
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

int IncomingTransaction::_callback(nta_incoming_magic_t* magic, nta_incoming_t*, const sip_t* sip) noexcept {
	IncomingTransaction* it = reinterpret_cast<IncomingTransaction*>(magic);
	LOGD("IncomingTransaction callback %p", it);
	if (sip != nullptr) {
		auto ev = make_shared<RequestSipEvent>(
		    it->shared_from_this(),
		    make_shared<MsgSip>(ownership::owned(nta_incoming_getrequest_ackcancel(it->mIncoming))));
		it->mAgent.lock()->sendRequestEvent(ev);
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
		// avoid callbacks
		nta_incoming_remove_custom_deinit(mIncoming);
		nta_incoming_bind(mIncoming, nullptr, nullptr);

		nta_incoming_destroy(mIncoming);
		mIncoming = nullptr;
		mSofiaRef.reset(); // This MUST be the last instruction of this function, because it may destroy the
		                   // IncomingTransaction.
	}
}