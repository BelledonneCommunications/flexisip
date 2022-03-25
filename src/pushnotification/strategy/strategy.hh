/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <memory>

#include "pushnotification/push-info.hh"
#include "pushnotification/request.hh"
#include "pushnotification/service.hh"

namespace flexisip {
namespace pushnotification {

class Strategy {
public:
	Strategy(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<Service>& service) noexcept
	    : mRoot{root}, mService{service} {
	}
	virtual ~Strategy() = default;

	virtual void sendMessageNotification(const std::shared_ptr<const PushInfo>& pInfo) = 0;
	virtual void sendCallNotification(const std::shared_ptr<const PushInfo>& pInfo) = 0;

protected:
	std::shared_ptr<sofiasip::SuRoot> mRoot{};
	std::shared_ptr<Service> mService{};
};

}; // namespace pushnotification
}; // namespace flexisip
