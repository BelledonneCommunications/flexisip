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

#include <stdexcept>

#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/module.hh"
#include "flexisip/pushnotification/pushnotification-context-observer.hh"

#include "pushnotification/contact-expiration-notifier.hh"
#include "pushnotification/service.hh"
#include "pushnotification/strategy/strategy.hh"
#include "utils/observable.hh"

#pragma once

namespace flexisip {

class PushNotification;

/**
 * Abstract class which PNContextCall and PNContextMessage inherit from.
 *
 * It is instantiated and held by PushNotification module class until the push notification which it is in charge
 * is actually sent to the according PN service. It may also be prematurely canceled to avoid useless PN sending
 * when a provisional response is received on its associated outgoing transaction.
 *
 * Once the PushNotificationContext is created, the start() method must be called to start a timer which will
 * trigger the PN after a given delay. A delay of 0s will cause the push notification to be sent asynchronously
 * as soon as possible. The kind and the payload of the PN to sent is affected by the sub-class used on construction
 * and the information stored in the PushInfo structure.
 */
class PushNotificationContext : public Observable<PushNotificationContextObserver>,
                                public std::enable_shared_from_this<PushNotificationContext> {
public:
	virtual ~PushNotificationContext();

	const std::string& getKey() const {
		return mKey;
	}
	const std::shared_ptr<const pushnotification::PushInfo>& getPushInfo() const noexcept {
		return mPInfo;
	}

	bool toTagEnabled() const noexcept {
		return mToTagEnabled;
	}
	void enableToTag(bool aEnabled) noexcept {
		mToTagEnabled = aEnabled;
	}

	/**
	 * Enable PN retransmission system.
	 * Allow to send the same push notification several times with a given time interval
	 * between each PNR.
	 * @param[in] retryCounter Number of retransmission. 0 means that only one PN will be sent.
	 * @param[in] retryInterval Delay between two subsequent push notifications.
	 */
	void setRetransmission(int retryCounter, std::chrono::seconds retryInterval) noexcept {
		mRetryCounter = retryCounter;
		mRetryInterval = retryInterval;
	}

	const std::shared_ptr<const pushnotification::Strategy> getStrategy() const {
		return mStrategy;
	}

	/**
	 * Schedule the sending of the push notification.
	 * @param[in] delay Delay before the PN is actually sent.
	 */
	void start(std::chrono::seconds delay);
	/**
	 * Cancel the sending of the push notification.
	 * That unschedules the PN sending if it hasn't been carry out yet and stop any further retransmissions.
	 */
	void cancel();

protected:
	// Protected ctors
	PushNotificationContext(const std::shared_ptr<OutgoingTransaction>& transaction,
	                        PushNotification* _module,
	                        const std::shared_ptr<const pushnotification::PushInfo>& pInfo,
	                        const std::string& pnKey);
	PushNotificationContext(const PushNotificationContext&) = delete;

	// Protected methods
	void onTimeout() noexcept;
	virtual void sendPush() = 0;
	void notifyPushSent(bool aRingingPush = false) {
		notify([this, aRingingPush](auto& aObserver) { aObserver.onPushSent(*this, aRingingPush); });
	}

	// Protected attributes
	std::string mKey{}; /**< unique key for the push notification, identifying the device and the call. */
	PushNotification* mModule{nullptr}; /**< Back pointer to the PushNotification module. */
	std::shared_ptr<const pushnotification::PushInfo> mPInfo{};
	std::weak_ptr<BranchInfo> mBranchInfo;
	std::weak_ptr<ForkContext> mForkContext;
	std::shared_ptr<pushnotification::Strategy>
	    mStrategy{};           /**< A delegate object that affect how the client will be notified. */
	sofiasip::Timer mTimer;    /**< timer after which push is sent */
	sofiasip::Timer mEndTimer; /**< timer to automatically remove the PN 30 seconds after starting */
	int mRetryCounter{0};
	std::chrono::seconds mRetryInterval{0};
	bool mToTagEnabled{false};

	// Friendship
	friend class pushnotification::Strategy; /**< Allow Strategy to invoke notifyPushSent(). */
};

class PushNotification : public Module {
	friend std::shared_ptr<Module> ModuleInfo<PushNotification>::create(Agent*);

public:
	~PushNotification() override = default;

	static bool needsPush(const std::shared_ptr<MsgSip>& msgSip);

	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;
	void onLoad(const GenericStruct* mc) override;

	const std::shared_ptr<pushnotification::Service>& getService() const {
		return mPNS;
	}

private:
	// Private types
	class InvalidMethodError : public std::invalid_argument {
	public:
		using std::invalid_argument::invalid_argument;
	};

	// Private methods
	PushNotification(Agent* ag, const ModuleInfoBase* moduleInfo);

	/**
	 * Gathers all the information required to create a PushNotificationContext
	 * and create an instance of it by using the right implementation. Then,
	 * add it to the map of pending notifications.
	 */
	void makePushNotification(const std::shared_ptr<MsgSip>& ms,
	                          const std::shared_ptr<OutgoingTransaction>& transaction);
	void removePushNotification(PushNotificationContext* pn);
	std::chrono::seconds getCallRemotePushInterval(const char* pushParams) const noexcept;

	static pushnotification::Method stringToGenericPushMethod(const std::string& methodStr);
	static pushnotification::Protocol stringToGenericPushProtocol(const std::string& protocolStr);

	// Private attributes
	std::map<std::string, std::shared_ptr<PushNotificationContext>>
	    mPendingNotifications; // map of pending push notifications. Its
	                           // purpose is to avoid sending multiples
	                           // notifications for the same call attempt
	                           // to a given device.
	static ModuleInfo<PushNotification> sInfo;
	std::shared_ptr<SipBooleanExpression> mAddToTagFilter{};
	std::chrono::seconds mTimeout{0};
	std::chrono::seconds mCallTtl{0};    // Push notification TTL for calls.
	std::chrono::seconds mMessageTtl{0}; // Push notification TTL for IM.
	unsigned mRetransmissionCount{0};
	std::chrono::seconds mRetransmissionInterval{0};
	std::chrono::seconds mCallRemotePushInterval{0};
	std::shared_ptr<pushnotification::Service> mPNS{};
	StatCounter64* mCountFailed{nullptr};
	StatCounter64* mCountSent{nullptr};
	bool mNoBadgeiOS{false};
	bool mDisplayFromUri{false};

	std::unique_ptr<ContactExpirationNotifier> mExpirationNotifier = nullptr;

	friend class PushNotificationContext;
};

} // namespace flexisip
