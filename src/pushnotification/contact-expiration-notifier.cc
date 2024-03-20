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

#include <ostream>

#include "contact-expiration-notifier.hh"
#include "push-notification-exceptions.hh"

#include "utils/transport/http/http-message.hh"

using namespace std;

namespace flexisip {

namespace pn = pushnotification;

namespace {

constexpr auto kLogPrefix = "[ContactExpirationNotifier] ";

// Abstraction to print the relevant device information of a contact
class DeviceInfo {
public:
	const ExtendedContact& contact;
};

ostream& operator<<(ostream& stream, const DeviceInfo& devInfo) {
	const auto& contact = devInfo.contact;
	return stream << "device '" << contact.mKey.str() << "' of user '" << contact.urlAsString() << "'";
}

} // namespace

ContactExpirationNotifier::ContactExpirationNotifier(chrono::seconds interval,
                                                     float lifetimeThreshold,
                                                     const shared_ptr<sofiasip::SuRoot>& root,
                                                     weak_ptr<pn::Service>&& pnService,
                                                     const RegistrarDb& registrar)
    : mLifetimeThreshold(lifetimeThreshold), mTimer(root, interval), mPNService(std::move(pnService)),
      mRegistrar(registrar) {
	// SAFETY: This lambda is safe memory-wise if and only if it doesn't outlive `this`.
	// Which is the case as long as `this` holds the sofiasip::Timer.
	mTimer.run([this] { onTimerElapsed(); });
}

void ContactExpirationNotifier::onTimerElapsed() {
	SLOGI << kLogPrefix << "Sending service push notifications to wake up mobile devices that have passed "
	      << mLifetimeThreshold << " of their expiration time...";
	mRegistrar.fetchExpiringContacts(
	    getCurrentTime(), mLifetimeThreshold, [weakPNService = mPNService](auto&& contacts) mutable {
		    static constexpr const auto pushType = pn::PushType::Background;
		    auto pnService = weakPNService.lock();
		    if (!pnService) {
			    SLOGI << kLogPrefix
			          << "Push notification service destructed, cannot send register wake up notifications "
			             "(This is expected if flexisip is being shut down)";
			    return;
		    }

		    for (const auto& contact : contacts) {
			    DeviceInfo devInfo{contact};
			    try {
				    const auto request = pnService->makeRequest(pushType, std::make_unique<pn::PushInfo>(contact));
				    if (auto* httpRequest = dynamic_cast<HttpMessage*>(request.get())) {
					    // We don't want those service notifications overtaking more important call or message
					    // notifications, so send with minimum priority
					    httpRequest->mPriority.weight = NGHTTP2_MIN_WEIGHT;
				    }

				    pnService->sendPush(request);

				    SLOGI << kLogPrefix << "background push notification successfully sent to " << devInfo;
			    } catch (const pn::UnavailablePushNotificationClient& e) {
				    SLOGD << kLogPrefix << "failed to send push notification to " << devInfo << ": " << e.what();
			    } catch (const exception& e) {
				    SLOGE << kLogPrefix << "failed to send push notification to " << devInfo << ": " << e.what();
			    }
		    }
	    });
}

unique_ptr<ContactExpirationNotifier> ContactExpirationNotifier::make_unique(const GenericStruct& cfg,
                                                                             const shared_ptr<sofiasip::SuRoot>& root,
                                                                             weak_ptr<pn::Service>&& pnService,
                                                                             const RegistrarDb& registrar) {
	auto interval =
	    chrono::duration_cast<chrono::minutes>(cfg.get<ConfigDuration<chrono::minutes>>("register-wakeup-interval")->read());
	if (interval <= 0min) {
		return nullptr;
	}
	float threshold = cfg.get<ConfigInt>("register-wakeup-threshold")->read() / 100.0;

	return std::make_unique<ContactExpirationNotifier>(interval, threshold, root, std::move(pnService), registrar);
}

} // namespace flexisip
