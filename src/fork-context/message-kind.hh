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

#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "sofia-sip/sip.h"

namespace flexisip {

/**
 * @brief Indicate if the SIP MESSAGE request is a 'one-to-one' message, is intended for the conference server of
 * coming from the conference server.
 */
class MessageKind {
public:
	enum class Cardinality : std::uint8_t {
		Direct,
		ToConferenceServer,
		FromConferenceServer,
	};

	MessageKind(const sip_t& event, sofiasip::MsgSipPriority priority);

	Cardinality getCardinality() const;
	sofiasip::MsgSipPriority getPriority() const;
	const std::optional<std::string>& getConferenceId() const;

private:
	Cardinality mCardinality;
	sofiasip::MsgSipPriority mPriority;
	std::optional<std::string> mConferenceId;
};

} // namespace flexisip