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

#include <chrono>
#include <string>

#include <sofia-sip/sip_status.h>

#include "flexisip/sofia-wrapper/timer.hh"

#include "module-pushnotification.hh"
#include "pushnotification/push-info.hh"
#include "strategy/strategy.hh"

namespace flexisip {

class PNContextCall : public PushNotificationContext {
public:
	static std::shared_ptr<PNContextCall> make(const std::shared_ptr<OutgoingTransaction>& transaction,
	                                           PushNotification* _module,
	                                           const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
	                                           std::chrono::seconds callPushInterval,
	                                           const std::string& pnKey) {
		auto obj = std::shared_ptr<PNContextCall>{new PNContextCall{transaction, _module, pInfo, pnKey}};
		obj->init(callPushInterval);
		return obj;
	}

	void sendPush() override;

private:
	using PushNotificationContext::PushNotificationContext;

	/**
	 * Post construction initializations.
	 */
	void init(std::chrono::seconds aCallPushInterval);
};

class PNContextMessage : public PushNotificationContext {
public:
	static std::shared_ptr<PNContextMessage> make(const std::shared_ptr<OutgoingTransaction>& transaction,
	                                              PushNotification* _module,
	                                              const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
	                                              const std::string& pnKey) {
		auto obj = std::shared_ptr<PNContextMessage>{new PNContextMessage{transaction, _module, pInfo, pnKey}};
		obj->init();
		return obj;
	}

	void sendPush() override;

private:
	using PushNotificationContext::PushNotificationContext;

	/**
	 * Post construction initializations.
	 */
	void init();
};

}; // namespace flexisip
