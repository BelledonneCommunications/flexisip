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

#include <sofia-sip/sip_extra.h>

#include "flexisip/sofia-wrapper/msg-sip.hh"

namespace flexisip {

/**
 * @return a P-Preferred-Identity when usable.
 *
 */
static sip_p_preferred_identity_t* preferredIdentity(const sofiasip::MsgSip& msg) {
	// RFC 3323-4.1.1.3 & RFC 3325-9.2
	const sip_t* sip = msg.getSip();
	const char* fromDomain = sip->sip_from->a_url[0].url_host;
	if (fromDomain && (strcmp(fromDomain, "anonymous.invalid") == 0)) return sip_p_preferred_identity(sip);

	return nullptr;
}
} // namespace flexisip