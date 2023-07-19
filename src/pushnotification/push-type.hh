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

#include <ostream>
#include <string>

namespace flexisip {
namespace pushnotification {

/**
 * An abstract type of push notification
*/
enum class PushType {
	Unknown,
	/**
	 * Push notification that only wakes the application up without showing any message to the user. That's the only
	 * kind of PN supported by Android. On iOS, it is implemented as a Remote PN without the 'alert' key in the payload.
	 */
	Background,
	/**
	 * Push notification that carries a message to display to the user. Not supported by Android. On iOS, it is
	 * implemented as a Remote PN with the 'alert' key defined in the body.
	 */
	Message,
	/**
	 * Push notification which is designed for incoming call notification. Not supported by Android. On iOS, it is
	 * implemented as a VoIP PN i.e. by using a topic suffixed by '.voip' and defining the 'apns-push-type' HTTP
	 * header to 'voip'.
	 */
	VoIP
};

const char* toCString(PushType type) noexcept;

inline std::string toString(PushType type) noexcept {
	return toCString(type);
}

inline std::ostream& operator<<(std::ostream& os, PushType type) noexcept {
	os << toCString(type);
	return os;
}

} // namespace pushnotification
} // namespace flexisip
