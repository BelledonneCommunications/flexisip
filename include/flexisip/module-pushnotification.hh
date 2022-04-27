/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module.hh"

#include "pushnotification/service.hh"
#include "sip-boolean-expressions.hh"

namespace flexisip {

class PushNotification;

class PushNotificationContext {
public:
	PushNotificationContext(const std::shared_ptr<OutgoingTransaction>& transaction,
	                        PushNotification* module,
	                        const std::shared_ptr<pushnotification::Request>& pnr,
	                        const std::string& pnKey,
	                        unsigned retryCount,
	                        unsigned retryInterval);
	PushNotificationContext(const PushNotificationContext&) = delete;
	~PushNotificationContext() = default;

	const std::string& getKey() const {
		return mKey;
	}
	const std::shared_ptr<pushnotification::Request>& getPushRequest() const {
		return mPushNotificationRequest;
	}

	void start(int seconds, bool sendRinging);
	void cancel();

private:
	void onTimeout();

	std::string mKey; // unique key for the push notification, identifiying the device and the call.
	PushNotification* mModule = nullptr;
	std::shared_ptr<pushnotification::Request> mPushNotificationRequest;
	std::shared_ptr<OutgoingTransaction> mTransaction;
	sofiasip::Timer mTimer;    // timer after which push is sent
	sofiasip::Timer mEndTimer; // timer to automatically remove the PN 30 seconds after starting
	int mRetryCounter = 0;
	unsigned mRetryInterval = 0;
	bool mSendRinging = true;
	bool mPushSentResponseSent = false; // whether the 110 Push sent was sent already
};

class PushNotification : public Module, public ModuleToolbox {
public:
	PushNotification(Agent* ag);
	~PushNotification() override = default;
	void onDeclare(GenericStruct* module_config) override;
	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override;
	void onLoad(const GenericStruct* mc) override;
	pushnotification::Service& getService() const {
		return *mPNS;
	}

private:
	bool needsPush(const sip_t* sip);
	void makePushNotification(const std::shared_ptr<MsgSip>& ms,
	                          const std::shared_ptr<OutgoingTransaction>& transaction);
	void removePushNotification(PushNotificationContext* pn);
	void parsePushParams(const std::shared_ptr<MsgSip>& ms, const char* params, pushnotification::PushInfo& pinfo);
	void
	parseLegacyPushParams(const std::shared_ptr<MsgSip>& ms, const char* params, pushnotification::PushInfo& pinfo);
	bool isGroupChatInvite(sip_t* sip);

	std::map<std::string, std::shared_ptr<PushNotificationContext>>
	    mPendingNotifications; // map of pending push notifications. Its
	                           // purpose is to avoid sending multiples
	                           // notifications for the same call attempt
	                           // to a given device.
	static ModuleInfo<PushNotification> sInfo;
	url_t* mExternalPushUri = nullptr;
	std::string mExternalPushMethod;
	std::shared_ptr<SipBooleanExpression> mAddToTagFilter{};
	int mTimeout = 0;
	int mCallTtl = 0;    // Push notification ttl for calls.
	int mMessageTtl = 0; // Push notification ttl for IM.
	unsigned mRetransmissionCount = 0;
	unsigned mRetransmissionInterval = 0;
	std::map<std::string, std::string> mFirebaseKeys;
	std::unique_ptr<pushnotification::Service> mPNS;
	StatCounter64* mCountFailed = nullptr;
	StatCounter64* mCountSent = nullptr;
	bool mNoBadgeiOS = false;
	bool mDisplayFromUri = false;

	friend class PushNotificationContext;
};

} // namespace flexisip
