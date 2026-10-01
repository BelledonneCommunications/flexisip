/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/utils/sip-uri.hh"
#include "uri-type.hh"

namespace flexisip::flexiapi {

struct CallForwarding {
	enum class Type {
		Always,
		NoAnswer,
	};

	Type type;
	UriType uriType;
	SipUri sip_uri{};
	bool enabled;
};

inline std::string toString(CallForwarding::Type type) {
	switch (type) {
		using enum CallForwarding::Type;
		case Always:
			return "always";
		case NoAnswer:
			return "no_answer";
		default:
			return "Invalid ForwardType";
	}
}
} // namespace flexisip::flexiapi