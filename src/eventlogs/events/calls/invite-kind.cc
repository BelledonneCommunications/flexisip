/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "invite-kind.hh"

#include <string_view>

#include "sofia-sip/sip.h"

using namespace std::string_view_literals;

namespace flexisip {

WithInviteKind::WithInviteKind(const sip_content_type_t& contentType) : mKind(InviteKind::Unknown) {
	const auto subtype = contentType.c_subtype;
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
