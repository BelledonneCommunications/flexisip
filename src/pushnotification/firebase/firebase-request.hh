/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "pushnotification/request.hh"
#include "utils/transport/http/http-message.hh"

namespace flexisip {
namespace pushnotification {

/**
 * This class represent one Firebase push notification request. This class inherits from Request, so it can be treated
 * like another type of PNR by the Flexisip push notification module, and from HttpMessage so it can be sent by the
 * Http2Client.
 *
 * This supports the legacy http (http2 compatible) Firebase protocol:
 * https://firebase.google.com/docs/cloud-messaging/http-server-ref
*/
class FirebaseRequest : public Request, public HttpMessage {
public:
	FirebaseRequest(PushType pType, const std::shared_ptr<const PushInfo>& pInfo);

private:
	static const std::chrono::seconds FIREBASE_MAX_TTL;
};

} // namespace pushnotification
} // namespace flexisip
