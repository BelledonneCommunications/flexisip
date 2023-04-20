/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "bctoolbox/tester.h"

#include "bellesip-utils.hh"

using namespace std;

namespace flexisip {

BellesipUtils::BellesipUtils(const string& ipaddress,
                             int port,
                             const string& transport,
                             const ProcessResponseEventCb& processResponseEventCb,
                             const ProcessRequestEventCb& processRequestEventCb) {
	mProcessResponseEventCb = processResponseEventCb;
	mProcessRequestEventCb = processRequestEventCb;
	mStack = belle_sip_stack_new(nullptr);
	mListeningPoint = belle_sip_stack_create_listening_point(mStack, ipaddress.c_str(), port, transport.c_str());
	mProvider = belle_sip_stack_create_provider(mStack, mListeningPoint);
	belle_sip_provider_add_listening_point(mProvider, mListeningPoint);

	belle_sip_listener_callbacks_t listener_callbacks{};
	listener_callbacks.process_response_event = [](void* userCtx, const belle_sip_response_event_t* event) {
		int status;
		auto thiz = static_cast<BellesipUtils*>(userCtx);
		if (!BC_ASSERT_PTR_NOT_NULL(belle_sip_response_event_get_response(event))) {
			return;
		}
		belle_sip_message("process_response_event [%i] [%s]",
		                  status = belle_sip_response_get_status_code(belle_sip_response_event_get_response(event)),
		                  belle_sip_response_get_reason_phrase(belle_sip_response_event_get_response(event)));

		if (thiz->mProcessResponseEventCb != nullptr) {
			thiz->mProcessResponseEventCb.operator()(status);
		}
	};

	listener_callbacks.process_request_event = [](void* userCtx, const belle_sip_request_event_t* event) {
		if (!BC_ASSERT_PTR_NOT_NULL(belle_sip_request_event_get_request(event))) {
			return;
		}
		belle_sip_message("caller_process_request_event received [%s] message",
		                  belle_sip_request_get_method(belle_sip_request_event_get_request(event)));
		auto thiz = static_cast<BellesipUtils*>(userCtx);
		belle_sip_response_t* resp;
		resp = belle_sip_response_create_from_request(belle_sip_request_event_get_request(event), 200);
		belle_sip_provider_send_response(thiz->mProvider, resp);

		if (thiz->mProcessRequestEventCb != nullptr) {
			thiz->mProcessRequestEventCb.operator()(event);
		}
	};

	mListener = belle_sip_listener_create_from_callbacks(&listener_callbacks, this);
	belle_sip_provider_add_sip_listener(mProvider, BELLE_SIP_LISTENER(mListener));
}

BellesipUtils::~BellesipUtils() {
	belle_sip_object_unref(mListener);
	belle_sip_object_unref(mProvider);
	belle_sip_object_unref(mStack);
}

void BellesipUtils::sendRawRequest(const string& rawMessage, const string& rawBody) {
	belle_sip_message_t* message = belle_sip_message_parse(rawMessage.c_str());
	belle_sip_request_t* request = BELLE_SIP_REQUEST(message);

	if (!rawBody.empty()) {
		belle_sip_message_set_body(BELLE_SIP_MESSAGE(request), rawBody.c_str(), rawBody.size());
	}

	belle_sip_provider_send_request(mProvider, request);
}

void BellesipUtils::stackSleep(unsigned int milliseconds) {
	belle_sip_stack_sleep(mStack, milliseconds);
}

} // namespace flexisip
