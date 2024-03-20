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

#include <stdexcept>
#include <string>
#include <utility>

#include <flexisip/logmanager.hh>

#include "generic/generic-enums.hh"
#include "rfc8599-push-params.hh"

namespace flexisip::pushnotification {

// Forward declaration to avoid circular dependency.
class Request;

/*
 * Base exception for all push notification related exceptions.
 */
class PushNotificationException : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};

/*
 * Report a misuse or a misconfiguration of push parameters.
 * Is also suitable for unsupported parameters.
 */
class InvalidPushParameters : public PushNotificationException {
public:
	using PushNotificationException::PushNotificationException;
};

/*
 * Report that a request requires an unknown push notification client.
 * Report that an application id is not mapped to an available push notification client.
 */
class UnavailablePushNotificationClient : public PushNotificationException {
public:
	explicit UnavailablePushNotificationClient(const RFC8599PushParams& params)
	    : PushNotificationException{"no push notification client available for AppID[" + params.getAppIdentifier() +
	                                "]"} {
	}
	explicit UnavailablePushNotificationClient(const Request* request)
	    : PushNotificationException{[request]() {
		      std::ostringstream message;
		      message << "no push notification client available for request[" << request << "]";
		      return message.str();
	      }()} {
	}
};

/*
 * Report that provided push type is not supported.
 */
class UnsupportedPushType : public PushNotificationException {
public:
	explicit UnsupportedPushType(PushType pushType)
	    : PushNotificationException{"no RFC8599 parameters found for '" + toString(pushType) +
	                                "' push notification type"} {
	}
};

/*
 * Report that no push parameters were found in the request uri.
 */
class MissingPushParameters : public PushNotificationException {
public:
	MissingPushParameters() : PushNotificationException{"no push parameters found in the request uri"} {
	}
};

/*
 * Report unauthorized HTTP methods in push notification clients.
 */
class UnauthorizedHttpMethod : public PushNotificationException {
public:
	explicit UnauthorizedHttpMethod(Method method)
	    : PushNotificationException{"invalid method value [" + std::to_string(static_cast<int>(method)) +
	                                "], authorized methods are HttpGet and HttpPost"} {
	}
};

/*
 * Report a problem with the sending parameters when sending a push notification.
 */
class InvalidSendParameters : public PushNotificationException {
public:
	using PushNotificationException::PushNotificationException;
};

} // namespace flexisip::pushnotification
