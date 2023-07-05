/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "sofia-sip/sip.h"

namespace flexisip {

enum class InviteKind {
	Call,
	ChatGroup,
	Unknown,
};

class WithInviteKind {
public:
	explicit WithInviteKind(const sip_content_type_t*);

	InviteKind getInviteKind() const {
		return mKind;
	}

private:
	InviteKind mKind;
};

} // namespace flexisip
