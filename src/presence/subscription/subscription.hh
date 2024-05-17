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

#include <string>

#include "belle-sip/belle-sip.h"

#include "flexisip/configmanager.hh"

#include "presence/presentity/presentity-presence-information-listener.hh"
#include "utils/belle-sip-utils.hh"

namespace flexisip {

class Subscription : public std::enable_shared_from_this<Subscription> {

public:
	enum class State { active, pending, terminated };
	Subscription(const std::string& eventName,
	             unsigned int expires,
	             const bellesip::weak_ptr<belle_sip_dialog_t>& aDialog,
	             belle_sip_provider_t* prov,
	             const std::weak_ptr<StatPair>& countSubscription);
	Subscription(const Subscription&) = delete;
	virtual ~Subscription();
	void setAcceptHeader(belle_sip_header_t* acceptHeader);
	void setAcceptEncodingHeader(belle_sip_header_t* acceptEncodingHeader);
	void setId(std::string_view id) {
		mId = id;
	}
	void notify(belle_sip_multipart_body_handler_t* body) {
		notify(nullptr, nullptr, body, nullptr);
	}
	void notify(belle_sip_multipart_body_handler_t* body, const std::string& content_encoding) {
		notify(nullptr, nullptr, body, &content_encoding);
	}
	void notify(belle_sip_header_content_type_t* content_type, const std::string& body) {
		notify(content_type, &body, nullptr, nullptr);
	}
	static const char* stateToString(State aState);
	State getState() const {
		return mState;
	}
	void setState(State state) {
		mState = state;
	}
	/*
	 * used to set expiration value
	 */
	void setExpirationTime(time_t expirationTime) {
		mExpirationTime = expirationTime;
	}
	time_t getExpirationDate();
	void increaseExpirationTime(unsigned int expires) {
		mExpirationTime += expires;
	}
	const belle_sip_uri_t* getFrom();
	const belle_sip_uri_t* getTo();

	belle_sip_client_transaction_t* mCurrentTransaction = nullptr;

protected:
	using BelleSipProviderPtr = std::unique_ptr<belle_sip_provider_t, BelleSipObjectDeleter<belle_sip_provider_t>>;

	static constexpr const char* sSubscriptionDataTag = "subscription";

	template <typename T, typename BelleSipObjectT>
	static void setSubscription(BelleSipObjectT* obj, const std::shared_ptr<T>& sub) {
		belle_sip_object_data_set(BELLE_SIP_OBJECT(obj), sSubscriptionDataTag, new std::shared_ptr<Subscription>{sub},
		                          [](void* data) { delete static_cast<std::shared_ptr<Subscription>*>(data); });
	}

	template <typename BelleSipObjectT>
	static std::shared_ptr<Subscription> getSubscription(const BelleSipObjectT* obj) {
		auto data = belle_sip_object_data_get(BELLE_SIP_OBJECT(obj), sSubscriptionDataTag);
		return data ? *static_cast<std::shared_ptr<Subscription>*>(data) : nullptr;
	}

	bellesip::weak_ptr<belle_sip_dialog_t> mDialog{};
	belle_sip_provider_t* mProv{nullptr};

private:
	using BelleSipHeaderPtr = std::unique_ptr<belle_sip_header_t, BelleSipObjectDeleter<belle_sip_header_t>>;

	void notify(belle_sip_header_content_type_t* content_type,
	            const std::string* body,
	            belle_sip_multipart_body_handler_t* multiPartBody,
	            const std::string* content_encoding);

	std::string mEventName;
	BelleSipHeaderPtr mAcceptHeader;
	BelleSipHeaderPtr mAcceptEncodingHeader;
	std::string mId;
	State mState{State::active};
	time_t mCreationTime{0};
	time_t mExpirationTime{0};
	const std::weak_ptr<StatPair> mCountSubscription;
};

/**
 ** Presence subscription object host a subscription to a presence entity. This object has the same live cycle has a
 *subscription dialog
 */
class PresenceSubscription : public Subscription, public PresentityPresenceInformationListener {
public:
	PresenceSubscription(unsigned int expires,
	                     const belle_sip_uri_t* presentity,
	                     const bellesip::weak_ptr<belle_sip_dialog_t>& aDialog,
	                     belle_sip_provider_t* aProv,
	                     const std::weak_ptr<StatPair>& countPresenceSubscription);
	~PresenceSubscription() override;

	const belle_sip_uri_t* getPresentityUri() const override {
		return mPresentity.get();
	}
	/*
	 * This function is call every time Presentity information need to be notified to a UA
	 */
	void onInformationChanged(PresentityPresenceInformation& presenceInformation, bool extented) override;
	void onExpired(PresentityPresenceInformation& presenceInformation) override;
	const belle_sip_uri_t* getFrom() override {
		return Subscription::getFrom();
	};
	const belle_sip_uri_t* getTo() override {
		return Subscription::getTo();
	};

private:
	using BelleSipUriPtr = std::unique_ptr<belle_sip_uri_t, BelleSipObjectDeleter<belle_sip_uri_t>>;
	BelleSipUriPtr mPresentity;
};
} // namespace flexisip
