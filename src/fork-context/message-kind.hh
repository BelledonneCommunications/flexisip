/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "sofia-sip/sip.h"

#include "flexisip/sofia-wrapper/msg-sip.hh"

namespace flexisip {

class MessageKind {
public:
	enum class Kind : std::uint8_t {
		Refer,
		Message,
	};

	// Is this a One-to-One message or is it going through the conference server?
	enum class Cardinality : std::uint8_t {
		Direct,
		ToConferenceServer,
		FromConferenceServer,
	};

	MessageKind(const ::sip_t&, sofiasip::MsgSipPriority);

	Kind getKind() const {
		return mKind;
	}
	Cardinality getCardinality() const {
		return mCardinality;
	}
	sofiasip::MsgSipPriority getPriority() const {
		return mPriority;
	}
	const std::optional<std::string_view>& getConferenceId() const {
		return mConferenceId;
	}

private:
	Kind mKind;
	Cardinality mCardinality;
	sofiasip::MsgSipPriority mPriority;
	std::optional<std::string_view> mConferenceId;
};

} // namespace flexisip
