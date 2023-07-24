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
#include <memory>

#include "flexisip/sofia-wrapper/timer.hh"

#include "fork-context/branch-info.hh"
#include "strategy.hh"

namespace flexisip::pushnotification {

class MessagePushStrategy : public Strategy,
                            public BranchInfoListener,
                            public std::enable_shared_from_this<MessagePushStrategy> {
public:
	template <typename... Args>
	static std::shared_ptr<MessagePushStrategy> make(Args&&... args) {
		return std::shared_ptr<MessagePushStrategy>{new MessagePushStrategy{std::forward<Args>(args)...}};
	};

	// Set the interval between two subsequent notifications when this strategy is used for call invite notification.
	void setCallPushInterval(std::chrono::seconds interval) noexcept {
		mCallPushInterval = interval;
	}

	bool pushRepetitionEnabled() const noexcept {
		return mCallPushInterval.count() > 0;
	}

	PushType getPushType() const override {
		return PushType::Message;
	}

	void sendMessageNotification(const std::shared_ptr<const PushInfo>& pInfo) override;
	void sendCallNotification(const std::shared_ptr<const PushInfo>& pInfo) override;

private:
	// Private ctor
	MessagePushStrategy(const std::weak_ptr<PushNotificationContext>& aPNContext,
	                    const std::shared_ptr<sofiasip::SuRoot>& aRoot,
	                    const std::shared_ptr<Service>& aService,
	                    const std::weak_ptr<BranchInfo>& aBr)
	    : Strategy{aPNContext, aRoot, aService}, mBranchInfo{aBr} {
	}

	// Private methods
	void onBranchCanceled(const std::shared_ptr<BranchInfo>& br, ForkStatus cancelReason) noexcept override;
	void onBranchCompleted(const std::shared_ptr<BranchInfo>& br) noexcept override;

	// Attributes
	std::weak_ptr<BranchInfo> mBranchInfo{};
	std::chrono::seconds mCallPushInterval{2};
	std::chrono::seconds mCallRingingTimeout{45};
	std::shared_ptr<PushInfo> mCallPushInfo{};
	std::unique_ptr<sofiasip::Timer> mCallRingingTimeoutTimer{};
};

inline std::ostream& operator<<(std::ostream& os, const MessagePushStrategy* s) noexcept {
	return (os << "RemotePushStrategy[" << static_cast<const void*>(s) << "]");
}
inline std::ostream& operator<<(std::ostream& os, const std::shared_ptr<MessagePushStrategy>& s) noexcept {
	return operator<<(os, s.get());
}

} // namespace flexisip::pushnotification
