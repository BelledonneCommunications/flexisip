/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ostream>

#include "contact-expiration-notifier.hh"

using namespace std;

namespace flexisip {

namespace pn = pushnotification;

namespace {

constexpr auto kLogPrefix = "ContactExpirationNotifier: ";

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
    : mLifetimeThreshold(lifetimeThreshold), mTimer(root, interval), mPNService(move(pnService)),
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

				    pnService->sendPush(pnService->makeRequest(pushType, std::make_unique<pn::PushInfo>(contact)));

				    SLOGI << kLogPrefix << "Background push notification successfully sent to " << devInfo;
			    } catch (const pushnotification::PushNotificationError& e) {
				    SLOGD << kLogPrefix << "Register wake-up PN for " << devInfo << " skipped: " << e.what();
			    } catch (const exception& e) {
				    SLOGE << kLogPrefix << "Could not send register wake-up notification to " << devInfo << ": "
				          << e.what();
			    }
		    }
	    });
}

unique_ptr<ContactExpirationNotifier> ContactExpirationNotifier::make_unique(const GenericStruct& cfg,
                                                                             const shared_ptr<sofiasip::SuRoot>& root,
                                                                             weak_ptr<pn::Service>&& pnService,
                                                                             const RegistrarDb& registrar) {
	auto interval = cfg.get<ConfigInt>("register-wakeup-interval")->read();
	if (interval <= 0) {
		return nullptr;
	}
	float threshold = cfg.get<ConfigInt>("register-wakeup-threshold")->read() / 100.0;

	return std::make_unique<ContactExpirationNotifier>(chrono::minutes(interval), threshold, root, move(pnService),
	                                                   registrar);
}

} // namespace flexisip
