/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "sofia-sip/sip.h"

namespace flexisip {

class MessageKind {
public:
	enum class Kind : std::uint8_t {
		Refer,
		IMDN,
		Message,
	};

	// Is this a One-to-One message or is it going through the conference server?
	enum class Cardinality : std::uint8_t {
		Direct,
		ToConferenceServer,
		FromConferenceServer,
	};

	MessageKind(const ::sip_t&);

	Kind getKind() const {
		return mKind;
	}
	Cardinality getCardinality() const {
		return mCardinality;
	}
	const std::optional<std::string_view>& getConferenceId() const {
		return mConferenceId;
	}

private:
	Kind mKind;
	Cardinality mCardinality;
	std::optional<std::string_view> mConferenceId;
};

} // namespace flexisip
