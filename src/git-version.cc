/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

// This is the only file allowed to include flexisip-version.h so only this
// translation unit will be rebuilt on every pipeline, and spare the rest of
// the volatile FLEXISIP_GIT_VERSION macro.

#include <flexisip/flexisip-version.h>
#include <flexisip/version.hh>

#ifndef FLEXISIP_GIT_VERSION
#define FLEXISIP_GIT_VERSION "undefined"
#endif

namespace flexisip {

std::string_view gitVersion() {
	return FLEXISIP_GIT_VERSION;
}

} // namespace flexisip
