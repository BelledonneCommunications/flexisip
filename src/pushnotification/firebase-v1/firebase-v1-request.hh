/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <memory>
#include <string>

#include "pushnotification/push-info.hh"
#include "pushnotification/push-type.hh"
#include "pushnotification/request.hh"
#include "utils/transport/http/http-message.hh"

namespace flexisip::pushnotification {

/**
 * This class represents a FirebaseV1 push notification request. This class inherits from Request, so it can be treated
 * like another type of PNR by the Flexisip push notification module, and from HttpMessage so it can be sent by the
 * Http2Client.
 *
 * This supports Firebase Cloud Messaging (FCM) V1 API.
 * https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages/send?hl=en
 */
class FirebaseV1Request : public Request, public HttpMessage {
public:
	FirebaseV1Request(PushType pType, const std::shared_ptr<const PushInfo>& pInfo, std::string_view projectId);

private:
	static constexpr std::chrono::seconds FIREBASE_MAX_TTL{4 * 7 * 24 * 3600}; // Equals 4 weeks;

	std::string mProjectId;
};

} // namespace flexisip::pushnotification