/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>
#include <ctime>
#include <list>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include "submodules/externals/sofia-sip/libsofia-sip-ua/sip/sofia-sip/sip_protos.h"

#include "flexisip/common.hh"
#include "flexisip/sofia-wrapper/home.hh"
#include "flexisip/utils/sip-uri.hh"

#include "contact-key.hh"
#include "pushnotification/push-param.hh"
#include "utils/utf8-string.hh"

namespace flexisip {

struct ExtendedContactCommon {
	std::string mCallId{};
	std::string mKey{};
	std::list<std::string> mPath{};

	ExtendedContactCommon(const std::list<std::string>& path, const std::string& callId, const std::string& key)
	    : mCallId{callId}, mKey{key}, mPath{path} {
	}

	ExtendedContactCommon(const std::string& route) : mPath{route} {
	}
};

struct ExtendedContact {
	class Record;
	friend class Record;

	std::string mCallId{};
	ContactKey mKey{}; // If the contact contains an identifier listed in Record::sLineFieldNames, then it is used as
	                   // key, otherwise a random string
	std::list<std::string> mPath{}; // list of urls as string (not enclosed with brakets)
	std::string mUserAgent{};
	sip_contact_t* mSipContact{nullptr}; // Full contact
	float mQ{1.0f};
	uint32_t mCSeq{0};
	std::list<std::string> mAcceptHeader{};
	uintptr_t mConnId{0}; // a unique id shared with associate t_port
	sofiasip::Home mHome{};
	bool mAlias{false};
	bool mUsedAsRoute{false}; /*whether the contact information shall be used as a route when forming a request, instead
	                      of replacing the request-uri*/

	bool mIsFallback = false; // boolean indicating whether this ExtendedContact is a fallback route or not. There is no
	                          // need for it to be serialized to database.

	PushParamList mPushParamList{};

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
	std::chrono::seconds getSipExpires() const {
		return mExpires;
	}
	// The time at which this contact should no longer receive calls
	std::time_t getSipExpireTime() const {
		return mRegisterTime + mExpires.count();
	}
	// The time at which the contact will no longer be valid. May be beyond the getSipExpireTime() if the custom
	// `message-expires=` field overrides it
	std::time_t getExpireTime() const {
		return mRegisterTime + std::max(mExpires, mMessageExpires).count();
	}
	bool isExpired() const {
		return getExpireTime() <= getCurrentTime();
	}

	static int resolveExpire(const char* contact_expire, int global_expire) {
		if (contact_expire) {
			return atoi(contact_expire);
		} else {
			if (global_expire >= 0) {
				return global_expire;
			} else {
				return -1;
			}
		}
	}

	static std::string urlToString(const url_t* url) {
		std::ostringstream ostr;
		sofiasip::Home home;
		char* tmp = url_as_string(home.home(), url);
		return std::string(tmp ? tmp : "");
	}
	// This function ensures compatibility with old redis record where url was stored with brakets.
	static std::string compatUrlToString(const char* url) {
		if (url[0] == '<' && url[1] != '\0') {
			return std::string(url, 1, strlen(url) - 2);
		}
		return std::string(url);
	}

	/* Converts the m_url field of the sofia sip contact to std::string */
	std::string urlAsString() const {
		return urlToString(mSipContact->m_url);
	}

	/* Extract printable device name from the User-Agent field */
	utils::Utf8String getDeviceName() const;

	std::string serializeAsUrlEncodedParams();

	std::string getOrgLinphoneSpecs() const;

	void extractInfoFromHeader(const char* urlHeaders);
	const std::string getMessageExpires(const msg_param_t* m_params);
	void init(bool initExpire = true);
	void extractInfoFromUrl(const char* full_url);

	ExtendedContact(const char* key, const char* fullUrl) : mKey(key) {
		extractInfoFromUrl(fullUrl);
		init();
	}

	ExtendedContact(const ExtendedContactCommon& common,
	                const sip_contact_t* sip_contact,
	                int global_expire,
	                uint32_t cseq,
	                time_t updateTime,
	                bool alias,
	                const std::list<std::string>& acceptHeaders,
	                const std::string& userAgent)
	    : mCallId(common.mCallId), mKey(common.mKey), mPath(common.mPath), mUserAgent(userAgent), mCSeq(cseq),
	      mAcceptHeader(acceptHeaders), mAlias(alias), mRegisterTime(updateTime), mExpires(global_expire) {

		mSipContact = sip_contact_dup(mHome.home(), sip_contact);
		mSipContact->m_next = nullptr;
		init();
	}

	/**
	 * Forge an ExtendedContact from a SIP URI. Optionaly, a route and
	 * the 'q' parameter of the Contact may be set.
	 * The new ExtendedConact has the maximum expiration date.
	 */
	ExtendedContact(const SipUri& url, const std::string& route, float q = 1.0)
	    : mPath({route}), mExpires(std::chrono::seconds::max()) {
		mSipContact = sip_contact_create(mHome.home(), reinterpret_cast<const url_string_t*>(url.get()), nullptr);
		q = std::min(1.0f, std::max(0.0f, q)); // force RFC compliance
		mSipContact->m_q = mHome.sprintf("%.3f", q);
		init(false); // MUST be called with [initExpire == false] to keep mExpires and mMessageExpires untouched to
		             // prevent the contact from expiring.
	}

	ExtendedContact(const ExtendedContact& ec)
	    : mCallId(ec.mCallId), mKey(ec.mKey), mPath(ec.mPath), mUserAgent(ec.mUserAgent), mSipContact(nullptr),
	      mQ(ec.mQ), mCSeq(ec.mCSeq), mAcceptHeader(ec.mAcceptHeader), mConnId(ec.mConnId), mHome(), mAlias(ec.mAlias),
	      mUsedAsRoute(ec.mUsedAsRoute), mIsFallback(ec.mIsFallback), mRegisterTime(ec.mRegisterTime),
	      mExpires(ec.mExpires), mMessageExpires(ec.mMessageExpires) {
		mSipContact = sip_contact_dup(mHome.home(), ec.mSipContact);
		mSipContact->m_next = nullptr;
	}

	std::ostream& print(std::ostream& stream, time_t _now = getCurrentTime(), time_t offset = 0) const;
	sip_contact_t* toSofiaContact(su_home_t* home) const;
	sip_route_t* toSofiaRoute(su_home_t* home) const;

	/*returns a new url_t where ConnId (private flexisip parameter) is removed*/
	url_t* toSofiaUrlClean(su_home_t* home);
	bool isSame(const ExtendedContact& otherContact) const;

private:
	time_t mRegisterTime{0};
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
