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

#pragma once

#include <belle-sip/belle-sip.h>

using belle_sip_dialog_terminated_event_t = struct belle_sip_dialog_terminated_event;
using belle_sip_io_error_event_t = struct belle_sip_io_error_event;
using belle_sip_listener_t = struct structbelle_sip_listener_t;
using belle_sip_main_loop_t = struct belle_sip_main_loop;
using belle_sip_request_event_t = struct belle_sip_request_event;
using belle_sip_response_event_t = struct belle_sip_response_event;
using belle_sip_source_t = struct belle_sip_source;
using belle_sip_timeout_event_t = struct belle_sip_timeout_event;
using belle_sip_transaction_terminated_event_t = struct belle_sip_transaction_terminated_event;

/**
 * Special deleter for belle_sip_source_t objects that cancels the timer in addition of decrementing the reference
 * counter
 */
struct BelleSipSourceCancelingDeleter {
	constexpr BelleSipSourceCancelingDeleter() noexcept = default;
	constexpr BelleSipSourceCancelingDeleter(BelleSipObjectDeleter<belle_sip_source_t>&&) noexcept {
	}
	void operator()(belle_sip_source_t* source) const noexcept {
		belle_sip_source_cancel(source);
		belle_sip_object_unref(source);
	}
};
