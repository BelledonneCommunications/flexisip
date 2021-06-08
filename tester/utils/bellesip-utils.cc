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

#include "bellesip-utils.hh"

#include "bctoolbox/tester.h"

using namespace std;

namespace flexisip {

BellesipUtils::BellesipUtils(const string ipaddress, const int port, const string transport,
                     const ProcessResponseEventCb& processResponseEventCb) {
	mProcessResponseEventCb = processResponseEventCb;
	mStack = belle_sip_stack_new(NULL);
	mListeningPoint = belle_sip_stack_create_listening_point(mStack, ipaddress.c_str(), port, transport.c_str());
	mProvider = belle_sip_stack_create_provider(mStack, mListeningPoint);
	belle_sip_provider_add_listening_point(mProvider, mListeningPoint);

	belle_sip_listener_callbacks_t listener_callbacks;
	listener_callbacks.process_dialog_terminated = nullptr;
	listener_callbacks.process_io_error = nullptr;
	listener_callbacks.process_request_event = nullptr;

	listener_callbacks.process_response_event = [](void* userCtx, const belle_sip_response_event_t* event) {
		int status;
		if (!BC_ASSERT_PTR_NOT_NULL(belle_sip_response_event_get_response(event))) {
			return;
		}
		belle_sip_message("process_response_event [%i] [%s]",
		                  status = belle_sip_response_get_status_code(belle_sip_response_event_get_response(event)),
		                  belle_sip_response_get_reason_phrase(belle_sip_response_event_get_response(event)));

		static_cast<ProcessResponseEventCb *>(userCtx)->operator ()(status);
	};

	listener_callbacks.process_timeout = nullptr;
	listener_callbacks.process_transaction_terminated = nullptr;
	listener_callbacks.process_auth_requested = nullptr;
	listener_callbacks.listener_destroyed = nullptr;
	mListener = belle_sip_listener_create_from_callbacks(&listener_callbacks, &mProcessResponseEventCb);
	belle_sip_provider_add_sip_listener(mProvider, BELLE_SIP_LISTENER(mListener));
}

BellesipUtils::~BellesipUtils(){
	belle_sip_object_unref(mListener);
	belle_sip_object_unref(mProvider);
	belle_sip_object_unref(mStack);
}

void BellesipUtils::sendRawRequest(string rawMessage) {
	belle_sip_message_t* message = belle_sip_message_parse(rawMessage.c_str());
	belle_sip_request_t* request = BELLE_SIP_REQUEST(message);

	belle_sip_provider_send_request(mProvider, request);
}

void BellesipUtils::stackSleep(unsigned int milliseconds) {
	belle_sip_stack_sleep(mStack, 100);
}

} // namespace flexisip
