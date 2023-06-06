/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "fork-context/message-kind.hh"

namespace flexisip {

class WithMessageKind {
public:
	explicit WithMessageKind(const MessageKind& kind) : mMessageKind(kind) {
	}

	const MessageKind& getMessageKind() const {
		return mMessageKind;
	}

private:
	const MessageKind mMessageKind;
};

} // namespace flexisip
