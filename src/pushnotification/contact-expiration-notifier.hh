/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <exception>

#include <bctoolbox/logging.h>

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/sofia-wrapper/timer.hh"

#include "pushnotification/push-info.hh"
#include "pushnotification/push-notification-error.hh"
#include "pushnotification/service.hh"
#include "registrar/registrar-db.hh"

using namespace std::chrono_literals;
namespace pn = flexisip::pushnotification;

namespace flexisip {

/**
 * Send wake up push notifications to devices that are nearing their expiration time to let them register again.
 */
class ContactExpirationNotifier {
	const std::chrono::seconds mExpirationFrame; // Notify devices that will expire in the next n seconds
	sofiasip::Timer mTimer;
	std::weak_ptr<pn::Service> mPNService;
	const RegistrarDb& mRegistrar;

public:
	ContactExpirationNotifier(std::chrono::seconds interval,
	                          const std::shared_ptr<sofiasip::SuRoot>& root,
	                          std::weak_ptr<pn::Service>&& pnService,
	                          const RegistrarDb& registrar)
	    : mExpirationFrame(interval * 3), // Give 3 opportunities to devices to register back. In case a PN does not
	                                      // come through, or something goes wrong
	      mTimer(root, interval), mPNService(std::move(pnService)), mRegistrar(registrar) {
		// SAFETY: This lambda is safe memory-wise iff it doesn't outlive `this`.
		// Which is the case as long as `this` holds the sofiasip::Timer.
		mTimer.run([this] { onTimerElapsed(); });
	}

	void onTimerElapsed() {
		mRegistrar.fetchExpiringContacts(
		    getCurrentTime(), mExpirationFrame, [weakPNService = mPNService](auto&& contacts) mutable {
			    static constexpr const auto pushType = pn::PushType::Background;
			    auto pnService = weakPNService.lock();
			    if (!pnService) {
				    SLOGI << "Push notification service destructed, cannot send register wake up notifications "
				             "(This is expected if flexisip is being shut down)";
				    return;
			    }

			    for (const auto& contact : contacts) {
				    try {
					    pnService->sendPush(pnService->makeRequest(pushType, std::make_unique<pn::PushInfo>(contact)));
				    } catch (const pushnotification::PushNotificationError& e) {
					    SLOGD << "Register wake-up PN for " << contact << " skipped: " << e.what();
				    } catch (const std::exception& e) {
					    SLOGE << "Could not send register wake-up notification to " << contact << ": " << e.what();
				    }
			    }
		    });
	}

	static std::unique_ptr<ContactExpirationNotifier> make_unique(const GenericStruct& cfg,
	                                                              const std::shared_ptr<sofiasip::SuRoot>& root,
	                                                              std::weak_ptr<pn::Service>&& pnService,
	                                                              const RegistrarDb& registrar) {
		auto interval = cfg.get<ConfigInt>("register-wakeup-interval")->read();
		if (interval <= 0) {
			return nullptr;
		}

		return std::make_unique<ContactExpirationNotifier>(std::chrono::minutes(interval), root, std::move(pnService),
		                                                   registrar);
	}
};

} // namespace flexisip
