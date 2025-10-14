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

#include "extended-contact.hh"

#include <chrono>

#include "sofia-sip/sip_tag.h"

#include "sofia-wrapper/utilities.hh"
#include "utils/uri-utils.hh"
#include "utils/utf8-string.hh"

using namespace std;

namespace flexisip {

ExtendedContact::ExtendedContact(const char* key, const char* fullUrl, const std::string& messageExpiresName)
    : mKey(key), mMessageExpiresName{messageExpiresName} {
	extractInfoFromUrl(fullUrl);
	init();
}

ExtendedContact::ExtendedContact(const ExtendedContactCommon& common,
                                 const sip_contact_t* sip_contact,
                                 int global_expire,
                                 uint32_t cseq,
                                 time_t updateTime,
                                 bool alias,
                                 const std::list<std::string>& acceptHeaders,
                                 const std::string& userAgent,
                                 const std::string& messageExpiresName)
    : mCallId(common.mCallId), mKey(common.mKey), mPath(common.mPath), mUserAgent(userAgent), mCSeq(cseq),
      mAcceptHeader(acceptHeaders), mAlias(alias), mRegisterTime(updateTime), mMessageExpiresName{messageExpiresName},
      mExpires(global_expire) {

	mSipContact = sip_contact_dup(mHome.home(), sip_contact);
	mSipContact->m_next = nullptr;
	init();
}

ExtendedContact::ExtendedContact(const SipUri& url,
                                 const std::string& route,
                                 const std::string& messageExpiresName,
                                 float q)
    : mPath({route}), mMessageExpiresName{messageExpiresName}, mExpires(std::chrono::seconds::max()) {
	mSipContact = sip_contact_create(mHome.home(), reinterpret_cast<const url_string_t*>(url.get()), nullptr);
	q = min(1.0f, max(0.0f, q)); // Enforce RFC compliance.
	mSipContact->m_q = mHome.sprintf("%.3f", q);
	// MUST be called with [initExpire == false] to keep mExpires and mMessageExpires untouched to prevent the contact
	// from expiring.
	init(false);
}

ExtendedContact::ExtendedContact(const ExtendedContact& ec)
    : mCallId(ec.mCallId), mKey(ec.mKey), mPath(ec.mPath), mUserAgent(ec.mUserAgent), mQ(ec.mQ), mCSeq(ec.mCSeq),
      mAcceptHeader(ec.mAcceptHeader), mConnId(ec.mConnId), mAlias(ec.mAlias), mUsedAsRoute(ec.mUsedAsRoute),
      mIsFallback(ec.mIsFallback), mRegisterTime(ec.mRegisterTime), mMessageExpiresName(ec.mMessageExpiresName),
      mExpires(ec.mExpires), mMessageExpires(ec.mMessageExpires) {
	mSipContact = sip_contact_dup(mHome.home(), ec.mSipContact);
	mSipContact->m_next = nullptr;
}

int ExtendedContact::resolveExpire(const char* contact_expire, int global_expire) {
	if (contact_expire) return atoi(contact_expire);
	if (global_expire >= 0) return global_expire;
	return -1;
}

std::string ExtendedContact::urlToString(const url_t* url) {
	std::ostringstream ostr;
	sofiasip::Home home;
	char* tmp = url_as_string(home.home(), url);
	return std::string(tmp ? tmp : "");
}

ostream& ExtendedContact::print(ostream& stream, time_t _now, time_t _offset) const {
	time_t now = _now;
	time_t offset = _offset;
	char buffer[256] = "UNDETERMINED";
	time_t expire = getExpireTime();
	expire += offset;
	struct tm* ptm = localtime(&expire);
	if (ptm != nullptr) {
		strftime(buffer, sizeof(buffer) - 1, "%c", ptm);
	}
	const auto expireAfter = expire - now;

	stream << "ExtendedContact[" << this << "]( ";
	stream << urlToString(mSipContact->m_url) << " path=\"";
	for (auto it = mPath.cbegin(); it != mPath.cend(); ++it) {
		if (it != mPath.cbegin()) stream << " ";
		stream << *it;
	}
	stream << "\"";
	stream << " user-agent=\"" << mUserAgent << "\"";
	stream << " alias=" << (mAlias ? "yes" : "no");
	if (!mAlias) stream << " uid=" << mKey.str();
	stream << " expire=" << expireAfter << " s (" << buffer << ")";
	stream << " )";
	return stream;

	// Example output:
	/* clang-format off

	ExtendedContact[0x61200022ce40]( sip:existing1@example.org path="" user-agent="" alias=no uid=test-contact-0 expire=87 s (Thu Feb  9 15:01:00 2023) )

	clang-format on */
}

string ExtendedContact::getOrgLinphoneSpecs() const {
	if (!mSipContact) return {};
	const char* specs = msg_params_find(mSipContact->m_params, "+org.linphone.specs");
	string result = specs ? string(specs) : string();
	return result;
}

string ExtendedContact::getMessageExpires(const msg_param_t* m_params) const {
	if (m_params == nullptr) return {};

	// Find message expires time in the contact parameters.
	string mss_expires(*m_params);
	string name_expires_mss = mMessageExpiresName;
	if (mss_expires.find(name_expires_mss + "=") == string::npos) return {};

	return mss_expires.substr(mss_expires.find(name_expires_mss + "=") + (strlen(name_expires_mss.c_str()) + 1));
}

sip_contact_t* ExtendedContact::toSofiaContact(su_home_t* home) const {
	mSipContact->m_next = nullptr;
	return sip_contact_dup(home, mSipContact);
}

sip_route_t* ExtendedContact::toSofiaRoute(su_home_t* home) const {
	sip_route_t* rbegin = nullptr;
	sip_route_t* r = nullptr;
	for (auto it = mPath.begin(); it != mPath.end(); ++it) {
		sip_route_t* newr = sip_route_format(home, "<%s>", (*it).c_str());
		if (!newr) {
			LOGE << "Cannot parse " << *it << " into route header";
			break;
		}
		if (!url_has_param(newr->r_url, "lr")) {
			url_param_add(home, newr->r_url, "lr");
		}
		if (rbegin == nullptr) {
			rbegin = newr;
		} else {
			r->r_next = newr;
		}
		r = newr;
	}
	return rbegin;
}

void ExtendedContact::extractInfoFromHeader(const char* urlHeaders) {
	if (urlHeaders) {
		sofiasip::Home home;
		msg_header_t* headers;
		char* stringHeaders = url_query_as_header_string(home.home(), urlHeaders);
		unique_ptr<msg_t, void (*)(msg_t*)> msg(msg_create(sip_default_mclass(), 0), msg_destroy);

		if (msg_header_parse_str(msg.get(), nullptr, stringHeaders) != 0) return;
		// We need to add a sip_request to validate msg_serialize() contidition
		if (msg_header_add_dup(
		        msg.get(), nullptr,
		        reinterpret_cast<msg_header_t*>(sip_request_make(home.home(), "MESSAGE sip:abcd SIP/2.0\r\n"))) != 0)
			return;
		if (msg_serialize(msg.get(), nullptr) != 0) return;
		msg_prepare(msg.get());

		headers = *msg_chain_head(msg.get());

		while (headers) {
			if (reinterpret_cast<msg_common_t*>(headers)->h_len > 0 &&
			    reinterpret_cast<msg_common_t*>(headers)->h_class->hc_name) {
				string valueStr;
				string keyStr = reinterpret_cast<msg_common_t*>(headers)->h_class->hc_name;

				valueStr.resize(reinterpret_cast<msg_common_t*>(headers)->h_len + 1);
				size_t written =
				    msg_header_field_e(&valueStr[0], reinterpret_cast<msg_common_t*>(headers)->h_len, headers, 0);
				valueStr.resize(written);

				transform(keyStr.begin(), keyStr.end(), keyStr.begin(),
				          [](unsigned char c) { return std::tolower(c); });

				if (keyStr == "path") {
					// We want to keep only the uri part of the paths.
					sip_path_t* path = sip_path_format(home.home(), "%s", valueStr.c_str());
					if (path) {
						mPath.push_back(url_as_string(home.home(), path->r_url));
					} else {
						LOGE << "Bad path [" << valueStr << "]";
					}
				} else if (keyStr == "accept") {
					mAcceptHeader.push_back(valueStr);
				} else if (keyStr == "user-agent") {
					mUserAgent = valueStr;
				}
			}
			headers = reinterpret_cast<msg_common_t*>(headers)->h_succ;
		}
	}
}

utils::Utf8String ExtendedContact::getDeviceName() const {
	const string& userAgent = mUserAgent;
	const auto begin = userAgent.find('(');
	string deviceName;
	if (begin != string::npos) {
		auto end = userAgent.find(')', begin);
		auto openingParenthesis = userAgent.find('(', begin + 1);
		while (openingParenthesis != string::npos && openingParenthesis < end) {
			openingParenthesis = userAgent.find('(', openingParenthesis + 1);
			end = userAgent.find(')', end + 1);
		}
		if (end != string::npos) {
			deviceName = userAgent.substr(begin + 1, end - (begin + 1));
		}
	}
	return deviceName;
}

string ExtendedContact::serializeAsUrlEncodedParams() const {
	string param{};
	stringstream stream{};
	sofiasip::Home home{};
	auto* contact = sip_contact_dup(home.home(), mSipContact);

	stream << "fs-conn-id=" << hex << mConnId;
	url_param_add(home.home(), contact->m_url, stream.str().c_str());

	param = "callid=" + UriUtils::escape(mCallId, UriUtils::sipUriParamValueReserved);
	url_param_add(home.home(), contact->m_url, param.c_str());

	param = "expires=" + to_string(mExpires.count());
	url_param_add(home.home(), contact->m_url, param.c_str());

	param = "cseq=" + to_string(mCSeq);
	url_param_add(home.home(), contact->m_url, param.c_str());

	param = "updatedAt=" + to_string(mRegisterTime);
	url_param_add(home.home(), contact->m_url, param.c_str());

	param = string{"alias="} + (mAlias ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, param.c_str());

	param = string{"usedAsRoute="} + (mUsedAsRoute ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, param.c_str());

	ostringstream path{};
	for (auto it = mPath.cbegin(); it != mPath.cend(); ++it) {
		if (it != mPath.cbegin()) path << ",";
		path << "<" << *it << ">";
	}

	ostringstream accept{};
	for (auto it = mAcceptHeader.cbegin(); it != mAcceptHeader.cend(); ++it) {
		if (it != mAcceptHeader.cbegin()) accept << ",";
		accept << *it;
	}

	contact->m_url->url_headers = sip_headers_as_url_query(home.home(), SIPTAG_PATH_STR(path.str().c_str()),
	                                                       SIPTAG_ACCEPT_STR(accept.str().c_str()),
	                                                       SIPTAG_USER_AGENT_STR(mUserAgent.c_str()), TAG_END());

	return {sip_header_as_string(home.home(), reinterpret_cast<sip_header_t const*>(contact))};
}

void ExtendedContact::init(bool initExpire) {
	if (mSipContact == nullptr) return;

	if (mSipContact->m_q) mQ = atof(mSipContact->m_q);

	if (const auto* param = msg_header_find_param(reinterpret_cast<msg_common_t const*>(mSipContact), "fs-conn-id"))
		mConnId = strtoul(param, nullptr, 16);

	if (initExpire) {
		mMessageExpires = chrono::seconds(atoi(getMessageExpires(mSipContact->m_params).c_str()));
		if (mSipContact->m_expires) mExpires = chrono::seconds(atoi(mSipContact->m_expires));
	}

	auto pnProvider = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-provider");
	auto pnPrId = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-prid");
	auto pnParam = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-param");
	if (!pnProvider.empty() && !pnPrId.empty() && !pnParam.empty()) {
		mPushParamList = PushParamList{pnProvider, pnPrId, pnParam};
	} else {
		auto appId = UriUtils::getParamValue(mSipContact->m_url->url_params, "app-id");
		auto pnType = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-type");
		auto pnTok = UriUtils::getParamValue(mSipContact->m_url->url_params, "pn-tok");
		if (!appId.empty() && !pnType.empty() && !pnTok.empty()) {
			mPushParamList = PushParamList{pnType, pnTok, appId, true};
		}
	}
}

void ExtendedContact::extractInfoFromUrl(const char* fullUrl) {
	sofiasip::Url url{};
	auto* tmp = sip_contact_make(mHome.home(), fullUrl);
	try {
		if (tmp == nullptr) {
			LOGD << "Could not parse " << fullUrl << " as contact, fallback to url instead";
			url = sofiasip::Url{fullUrl};
		} else {
			url = sofiasip::Url{tmp->m_url};
		}
	} catch (const std::exception& e) {
		LOGE << "Failed to parse url: " << e.what();
		return;
	}

	if (url.empty()) {
		LOGE << "Url is empty";
		return;
	}

	mConnId = url.extractParam<uintptr_t>("fs-conn-id");
	mCallId = url.extractParam<string>("callid");
	mExpires = chrono::seconds{url.extractParam<int>("expires")};
	mRegisterTime = url.extractParam<time_t>("updatedAt");
	mCSeq = url.extractParam<int>("cseq");
	mAlias = url.extractParam<bool>("alias");
	mUsedAsRoute = url.extractParam<bool>("usedAsRoute");

	extractInfoFromHeader(url.getHeaders().c_str());

	url = url.replace(&url_t::url_headers, "");

	if (tmp == nullptr) {
		mSipContact = sip_contact_create(mHome.home(), sofiasip::toSofiaSipUrlUnion(url.str()), nullptr);
	} else {
		*tmp->m_url = *url_hdup(mHome.home(), url.get());
		mSipContact = tmp;
	}
}

bool ExtendedContact::isSame(const ExtendedContact& otherContact) const {
	return mCallId == otherContact.mCallId && mKey == otherContact.mKey &&
	       url_cmp_all(mSipContact->m_url, otherContact.mSipContact->m_url) == 0;
	/* FIXME: the comparison is not complete */
}

} // namespace flexisip