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

namespace flexisip {

class PushNotificationContext;

/**
 * Interface for PushNotificationContext observers.
 */
class PushNotificationContextObserver {
public:
	virtual ~PushNotificationContextObserver() = default;
	/**
	 * Notify the observer that a push notification has been sent by the PushNotificationContext.
	 * @param aPNCtx The PushNotificationContext that has sent the PN.
	 * @param aRingingPush Tells whether the sent PN makes the callee's device to ring without
	 * waking the user agent up.
	 */
	virtual void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept = 0;
};

} // namespace flexisip
