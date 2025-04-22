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

#include <optional>
#include <string>

#include "flexiapi/schemas/optional-json.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"
#include "pushnotification/push-type.hh"

namespace flexisip::pushnotification {
NLOHMANN_JSON_SERIALIZE_ENUM(PushType,
                             {
                                 {PushType::Background, "background"},
                                 {PushType::Message, "message"},
                                 {PushType::VoIP, "call"},
                             })
}

namespace flexisip::flexiapi {
class PushNotification {
public:
	PushNotification(const std::string& pnProvider,
	                 const std::optional<std::string>& pnParam,
	                 const std::optional<std::string>& pnPrid,
	                 const pushnotification::PushType& type,
	                 const std::optional<std::string>& callId)
	    : pn_provider(pnProvider), pn_param(pnParam), pn_prid(pnPrid), type(type), call_id(callId) {
	}

	NLOHMANN_DEFINE_TYPE_INTRUSIVE(PushNotification, pn_provider, pn_param, pn_prid, type, call_id);

private:
	// required, the push notification provider, must be in ['apns.dev', 'apns' or 'fcm']
	std::string pn_provider;
	// the push notification parameter, can be null or contain only alphanumeric and underscore characters
	std::optional<std::string> pn_param;
	// the push notification unique id, can be null or contain only alphanumeric, dashes and colon characters
	std::optional<std::string> pn_prid;
	// required, must be in ['background', 'message' or 'call']
	pushnotification::PushType type;
	// a Call ID, must have only alphanumeric and dashes characters
	std::optional<std::string> call_id;
};

} // namespace flexisip::flexiapi
