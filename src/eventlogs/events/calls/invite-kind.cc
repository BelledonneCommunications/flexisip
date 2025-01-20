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

#include "invite-kind.hh"

#include <string_view>

#include "sofia-sip/sip.h"

using namespace std::string_view_literals;

namespace flexisip {

WithInviteKind::WithInviteKind(const sip_content_type_t* contentType) : mKind(InviteKind::Unknown) {
	/*
	   "The Content-Type header field MUST be present if the body is not empty." RFC 3261 §20.15
	   In other words: It CAN be missing if the body is empty.
	*/
	if (contentType == nullptr) return;
	const auto subtype = contentType->c_subtype;
	if (subtype == nullptr) return;
	if (subtype == "resource-lists+xml"sv) {
		mKind = InviteKind::ChatGroup;
		return;
	}
	if (subtype == "sdp"sv) {
		mKind = InviteKind::Call;
		return;
	}
}

} // namespace flexisip