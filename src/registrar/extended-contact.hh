/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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
#include <ctime>
#include <list>
#include <sstream>
#include <string>

#include "sofia-sip/sip_protos.h"

#include "contact-key.hh"
#include "flexisip/common.hh"
#include "flexisip/sofia-wrapper/home.hh"
#include "flexisip/utils/sip-uri.hh"
#include "pushnotification/push-param.hh"
#include "utils/utf8-string.hh"

namespace flexisip {

struct ExtendedContactCommon {
	ExtendedContactCommon(const std::list<std::string>& path, const std::string& callId, const std::string& key)
	    : mCallId{callId}, mKey{key}, mPath{path} {};

	explicit ExtendedContactCommon(const std::string& route) : mPath{route} {};

	std::string mCallId{};
	std::string mKey{};
	std::list<std::string> mPath{};
};

struct ExtendedContact {
	class Record;
	friend class Record;

	ExtendedContact(const char* key, const char* fullUrl, const std::string& messageExpiresName);
	ExtendedContact(const ExtendedContactCommon& common,
	                const sip_contact_t* sip_contact,
	                int global_expire,
	                uint32_t cseq,
	                time_t updateTime,
	                bool alias,
	                const std::list<std::string>& acceptHeaders,
	                const std::string& userAgent,
	                const std::string& messageExpiresName);
	/**
	 * @brief Create an ExtendedContact from a SIP URI.
	 *
	 * @note Optionally, a route and the 'q' parameter of the Contact may be set. The new instance has the maximum
	 * expiration date.
	 */
	ExtendedContact(const SipUri& url, const std::string& route, const std::string& messageExpiresName, float q = 1.0);
	ExtendedContact(const ExtendedContact& ec);

	static int resolveExpire(const char* contact_expire, int global_expire);
	static std::string urlToString(const url_t* url);

	const char* callId() const {
		return mCallId.c_str();
	}
	std::string contactId() const {
		// A contact identifies by its unique-id if given. Otherwise, it identifies thanks to its sip uri.
		if (!mKey.isPlaceholder()) return mKey.str();
		return urlAsString();
	}
	const char* route() const {
		return (mPath.empty() ? nullptr : mPath.cbegin()->c_str());
	}
	const char* userAgent() const {
		return mUserAgent.c_str();
	}
	const std::string& getUserAgent() const {
		return mUserAgent;
	}
	std::time_t getRegisterTime() const {
		return mRegisterTime;
	}
	void setRegisterTime(time_t value) {
		mRegisterTime = value;
	};
	std::chrono::seconds getSipExpires() const {
		return mExpires;
	}
	/**
	 * @return the time at which this contact should no longer receive calls
	 */
	std::time_t getSipExpireTime() const {
		return mRegisterTime + mExpires.count();
	}
	/**
	 * @return the time at which the contact will no longer be valid. May be beyond the getSipExpireTime() if the custom
	 * `message-expires=` field overrides it
	 */
	std::time_t getExpireTime() const {
		return mRegisterTime + std::max(mExpires, mMessageExpires).count();
	}
	bool isExpired() const {
		return getExpireTime() <= getCurrentTime();
	}
	/**
	 * @return the m_url field of the sofia sip contact converted into a std::string
	 */
	std::string urlAsString() const {
		return urlToString(mSipContact->m_url);
	}
	/**
	 * @return a printable device name from the User-Agent field
	 */
	utils::Utf8String getDeviceName() const;

	std::string serializeAsUrlEncodedParams() const;

	std::string getOrgLinphoneSpecs() const;

	void extractInfoFromHeader(const char* urlHeaders);
	std::string getMessageExpires(const msg_param_t* m_params) const;
	void init(bool initExpire = true);
	void extractInfoFromUrl(const char* fullUrl);

	std::ostream& print(std::ostream& stream, time_t _now = getCurrentTime(), time_t offset = 0) const;
	sip_contact_t* toSofiaContact(su_home_t* home) const;
	/**
	 * @brief Convert the list of paths into sofia route.
	 */
	sip_route_t* toSofiaRoute(su_home_t* home) const;

	bool isSame(const ExtendedContact& otherContact) const;

	sofiasip::Home mHome{};
	std::string mCallId{};
	ContactKey mKey{}; // If the contact contains an identifier listed in Record::sLineFieldNames, then it is used as
	                   // the key, otherwise a random string.
	std::list<std::string> mPath{}; // List of urls as string (not enclosed in brackets).
	std::string mUserAgent{};
	sip_contact_t* mSipContact{nullptr}; // Full contact.
	float mQ{1.0f};
	uint32_t mCSeq{0};
	std::list<std::string> mAcceptHeader{};
	uintptr_t mConnId{0}; // A unique id shared with associate t_port.
	bool mAlias{false};
	bool mUsedAsRoute{false}; // Whether the contact information shall be used as a route when forming a request,
	                          // instead of replacing the request-uri.
	bool mIsFallback = false; // Whether this ExtendedContact is a fallback route or not. There is no need for it to be
	                          // serialized into the database.
	PushParamList mPushParamList{};

private:
	static constexpr std::string_view mLogPrefix{"ExtendedContact"};

	time_t mRegisterTime{0};
	std::string mMessageExpiresName;
	std::chrono::seconds mExpires{0};        // Standard SIP expires= field
	std::chrono::seconds mMessageExpires{0}; // Custom message-expires= override
};

template <typename TraitsT>
inline std::basic_ostream<char, TraitsT>& operator<<(std::basic_ostream<char, TraitsT>& strm,
                                                     const ExtendedContact& ec) {
	ec.print(strm);
	return strm;
}

} // namespace flexisip