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

#include <chrono>
#include <string>

#include <sofia-sip/sip_status.h>

#include "flexisip/module-pushnotification.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "flexisip/transaction.hh"

#include "pushnotification/push-info.hh"
#include "strategy/strategy.hh"

namespace flexisip {

class PNContextCall : public PushNotificationContext {
public:
	PNContextCall(const std::shared_ptr<OutgoingTransaction>& transaction,
	              PushNotification* _module,
	              const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
	              std::chrono::seconds callPushInterval,
	              const std::string& pnKey);

	void sendPush() override;
};

class PNContextMessage : public PushNotificationContext {
public:
	PNContextMessage(const std::shared_ptr<OutgoingTransaction>& transaction,
	                 PushNotification* _module,
	                 const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
	                 const std::string& pnKey);

	void sendPush() override;
};

}; // namespace flexisip
