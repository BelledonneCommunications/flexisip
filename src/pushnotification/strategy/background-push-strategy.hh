/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

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

#include "strategy.hh"

#pragma once

namespace flexisip {
namespace pushnotification {

class BackgroundPushStrategy : public Strategy {
public:
	template <typename... Args>
	static std::shared_ptr<BackgroundPushStrategy> make(Args&&... args) {
		return std::shared_ptr<BackgroundPushStrategy>{new BackgroundPushStrategy{std::forward<Args>(args)...}};
	}

	void sendMessageNotification(const std::shared_ptr<const PushInfo>& pInfo) override {
		auto req = mService->makeRequest(PushType::Background, pInfo);
		mService->sendPush(req);
		notifyPushSent();
	}
	void sendCallNotification(const std::shared_ptr<const PushInfo>& pInfo) override {
		auto req = mService->makeRequest(PushType::Background, pInfo);
		mService->sendPush(req);
		notifyPushSent();
	}

private:
	using Strategy::Strategy;
};

} // namespace pushnotification
} // namespace flexisip
