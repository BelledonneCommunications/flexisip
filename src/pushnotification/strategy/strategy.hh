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

#include <memory>

#include "pushnotification/push-info.hh"
#include "pushnotification/request.hh"
#include "pushnotification/service.hh"

namespace flexisip {

class PushNotificationContext;

namespace pushnotification {

class Strategy {
public:
	virtual ~Strategy() = default;

	virtual void sendMessageNotification(const std::shared_ptr<const PushInfo>& pInfo) = 0;
	virtual void sendCallNotification(const std::shared_ptr<const PushInfo>& pInfo) = 0;

protected:
	// Protected ctors
	Strategy(const std::weak_ptr<PushNotificationContext>& aPNContext,
	         const std::shared_ptr<sofiasip::SuRoot>& aRoot,
	         const std::shared_ptr<Service>& aService) noexcept
	    : mPNContext{aPNContext}, mRoot{aRoot}, mService{aService} {
	}

	// Protected methods
	/**
	 * Request the associated PushNotificationContext to notify its observers
	 * that a push notification has been sent.
	 * @param aRinging Tell whether the sent PN makes the callee's device to
	 * ring without waking the SIP user agent up.
	 */
	void notifyPushSent(bool aRinging = false);

	// Protected attributes
	std::weak_ptr<PushNotificationContext>
	    mPNContext{}; /**< Back pointer to the PushNotificationContext that owns this Strategy object. */
	std::shared_ptr<sofiasip::SuRoot> mRoot{};
	std::shared_ptr<Service> mService{};
};

}; // namespace pushnotification
}; // namespace flexisip
