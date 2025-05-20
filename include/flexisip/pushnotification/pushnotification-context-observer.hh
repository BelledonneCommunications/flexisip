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

namespace flexisip {

class PushNotificationContext;

/**
 * @brief Be notified when a push notification is sent by an instance of PushNotificationContext.
 */
class PushNotificationContextObserver {
public:
	virtual ~PushNotificationContextObserver();

	/**
	 * @brief Notify the observer that a push notification has been sent by the provided context.
	 *
	 * @param aPNCtx the context that has sent the push notification
	 * @param aRingingPush indicates whether the push notification sent made the callee's device to ring without waking
	 * the user agent up
	 */
	virtual void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept = 0;
};

} // namespace flexisip