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
	const std::optional<std::string>& getConferenceId() const {
		return mConferenceId;
	}

private:
	Kind mKind;
	Cardinality mCardinality;
	sofiasip::MsgSipPriority mPriority;
	std::optional<std::string> mConferenceId;
};

} // namespace flexisip