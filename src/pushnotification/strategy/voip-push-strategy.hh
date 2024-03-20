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

#include "strategy.hh"

namespace flexisip {
namespace pushnotification {

class VoIPPushStrategy : public Strategy {
public:
	template <typename... Args>
	static std::shared_ptr<VoIPPushStrategy> make(Args&&... args) {
		return std::shared_ptr<VoIPPushStrategy>{new VoIPPushStrategy{std::forward<Args>(args)...}};
	}

	void sendMessageNotification([[maybe_unused]] const std::shared_ptr<const PushInfo>& pInfo) override {
		throw std::logic_error{__PRETTY_FUNCTION__ + std::string{"() not implemented"}};
	}
	void sendCallNotification(const std::shared_ptr<const PushInfo>& pInfo) override {
		auto req = mService->makeRequest(PushType::VoIP, pInfo);
		mService->sendPush(req);
		notifyPushSent();
	}

	PushType getPushType() const override {
		return PushType::VoIP;
	}

private:
	using Strategy::Strategy;
};

} // namespace pushnotification
} // namespace flexisip
