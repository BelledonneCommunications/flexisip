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

#include "bellesip-timer.hh"

namespace belle_sip {

BelleSipSourceCancelingPtr createTimer(belle_sip_main_loop_t* mainLoop,
                                       const belle_sip_source_cpp_func_t& callback,
                                       unsigned int timeout,
                                       const char* timerName) {
	return belle_sip_main_loop_create_cpp_timeout(mainLoop, callback, timeout, timerName);
}

} // namespace belle_sip