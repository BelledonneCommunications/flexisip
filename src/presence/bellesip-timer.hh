/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "belle-sip-using.hh"

namespace belle_sip {

/**
 * Create a new Bellesip timer.
 * Note: it will cancels itself in case it is freed.

 * @param mainLoop The main loop to attach the timer to.
 * @param callback The callback function to be called when the timer expires.
 * @param timeout The timeout value in milliseconds.
 * @param timerName The name of the timer.
 */
BelleSipSourceCancelingPtr createTimer(belle_sip_main_loop_t* mainLoop,
                                       const belle_sip_source_cpp_func_t& callback,
                                       unsigned int timeout,
                                       const char* timerName);

} // namespace belle_sip