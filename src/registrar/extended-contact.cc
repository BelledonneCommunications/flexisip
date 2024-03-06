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

#include "extended-contact.hh"

#include <chrono>

#include <sofia-sip/sip_tag.h>

#include "utils/uri-utils.hh"
#include "utils/utf8-string.hh"

using namespace std;

namespace flexisip {

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
	int expireAfter = expire - now;

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

url_t* ExtendedContact::toSofiaUrlClean(su_home_t* home) {
	url_t* ret = nullptr;
	if (!mSipContact) return nullptr;

	ret = url_hdup(home, mSipContact->m_url);
	ret->url_params = url_strip_param_string((char*)ret->url_params, "fs-conn-id");
	return ret;
}

string ExtendedContact::getOrgLinphoneSpecs() const {
	if (!mSipContact) return string();
	const char* specs = msg_params_find(mSipContact->m_params, "+org.linphone.specs");
	string result = specs ? string(specs) : string();
	return result;
}

const string ExtendedContact::getMessageExpires(const msg_param_t* m_params) {
	if (m_params) {
		// Find message expires time in the contact parameters
		string mss_expires(*m_params);
		string name_expires_mss = mMessageExpiresName;
		if (mss_expires.find(name_expires_mss + "=") != string::npos) {
			mss_expires =
			    mss_expires.substr(mss_expires.find(name_expires_mss + "=") + (strlen(name_expires_mss.c_str()) + 1));
			return mss_expires;
		}
	}
	return "";
}

sip_contact_t* ExtendedContact::toSofiaContact(su_home_t* home) const {
	mSipContact->m_next = nullptr;
	return sip_contact_dup(home, mSipContact);
}

/*
 * Convert list of paths into sofia route.
 */
sip_route_t* ExtendedContact::toSofiaRoute(su_home_t* home) const {
	sip_route_t* rbegin = nullptr;
	sip_route_t* r = nullptr;
	for (auto it = mPath.begin(); it != mPath.end(); ++it) {
		sip_route_t* newr = sip_route_format(home, "<%s>", (*it).c_str());
		if (!newr) {
			LOGE("Cannot parse %s into route header", (*it).c_str());
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
						LOGE("ExtendedContact::extractInfoFromHeader(): bad path [%s]", valueStr.c_str());
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
	size_t begin = userAgent.find("(");
	string deviceName;
	if (begin != string::npos) {
		size_t end = userAgent.find(")", begin);
		size_t openingParenthesis = userAgent.find("(", begin + 1);
		while (openingParenthesis != string::npos && openingParenthesis < end) {
			openingParenthesis = userAgent.find("(", openingParenthesis + 1);
			end = userAgent.find(")", end + 1);
		}
		if (end != string::npos) {
			deviceName = userAgent.substr(begin + 1, end - (begin + 1));
		}
	}
	return deviceName;
}

string ExtendedContact::serializeAsUrlEncodedParams() {
	sofiasip::Home home;
	string param{};
	sip_contact_t* contact = sip_contact_dup(home.home(), mSipContact);

	// CallId
	param = "callid=" + UriUtils::escape(mCallId, UriUtils::sipUriParamValueReserved);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Expire
	param = "expires=" + to_string(mExpires.count());
	url_param_add(home.home(), contact->m_url, param.c_str());

	// CSeq
	param = "cseq=" + to_string(mCSeq);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Updated at
	param = "updatedAt=" + to_string(mRegisterTime);
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Alias
	param = string{"alias="} + (mAlias ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Used as route
	param = string{"usedAsRoute="} + (mUsedAsRoute ? "yes" : "no");
	url_param_add(home.home(), contact->m_url, param.c_str());

	// Path
	ostringstream oss_path{};
	for (auto it = mPath.cbegin(); it != mPath.cend(); ++it) {
		if (it != mPath.cbegin()) oss_path << ",";
		oss_path << "<" << *it << ">";
	}

	// AcceptHeaders
	ostringstream oss_accept{};
	for (auto it = mAcceptHeader.cbegin(); it != mAcceptHeader.cend(); ++it) {
		if (it != mAcceptHeader.cbegin()) oss_accept << ",";
		oss_accept << *it;
	}

	contact->m_url->url_headers = sip_headers_as_url_query(home.home(), SIPTAG_PATH_STR(oss_path.str().c_str()),
	                                                       SIPTAG_ACCEPT_STR(oss_accept.str().c_str()),
	                                                       SIPTAG_USER_AGENT_STR(mUserAgent.c_str()), TAG_END());

	string contact_string{sip_header_as_string(home.home(), (sip_header_t const*)contact)};
	return contact_string;
}

void ExtendedContact::init(bool initExpire) {
	if (mSipContact) {
		if (mSipContact->m_q) {
			mQ = atof(mSipContact->m_q);
		}

		if (url_has_param(mSipContact->m_url, "fs-conn-id")) {
			char strConnId[32] = {0};
			if (url_param(mSipContact->m_url->url_params, "fs-conn-id", strConnId, sizeof(strConnId) - 1) > 0) {
				mConnId = std::strtoull(strConnId, nullptr, 16);
			}
		}

		if (initExpire) {
			mMessageExpires = chrono::seconds(atoi(getMessageExpires(mSipContact->m_params).c_str()));
			if (mSipContact->m_expires) {
				mExpires = chrono::seconds(atoi(mSipContact->m_expires));
			}
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
}

static std::string extractStringParam(url_t* url, const char* param) noexcept {
	if (!url_has_param(url, param)) {
		return string{};
	}

	string buffer(255, '\0');
	auto valueLength = url_param(url->url_params, param, &buffer[0], buffer.size());
	buffer.resize(valueLength - 1);
	url->url_params = url_strip_param_string(const_cast<char*>(url->url_params), param);
	return UriUtils::unescape(buffer);
}

static int extractIntParam(url_t* url, const char* param) noexcept {
	try {
		return stoi(extractStringParam(url, param));
	} catch (...) {
		return 0;
	}
}

static int extractUnsignedLongParam(url_t* url, const char* param) noexcept {
	try {
		return static_cast<int>(stoll(extractStringParam(url, param)));
	} catch (...) {
		return 0;
	}
}

static bool extractBoolParam(url_t* url, const char* param) noexcept {
	auto extractedParam = extractStringParam(url, param);
	return !extractedParam.empty() && extractedParam.find("yes") != string::npos;
}

void ExtendedContact::extractInfoFromUrl(const char* full_url) {
	sip_contact_t* temp_contact = sip_contact_make(mHome.home(), full_url);
	url_t* url = nullptr;
	if (temp_contact == nullptr) {
		SLOGD << "Couldn't parse " << full_url << " as contact, fallback to url instead";
		url = url_make(mHome.home(), full_url);
	} else {
		url = temp_contact->m_url;
	}

	if (url == nullptr) {
		LOGE("ExtendedContact::extractInfoFromUrl() url is null.");
		return;
	}

	// CallId
	mCallId = extractStringParam(url, "callid");

	// Expire
	mExpires = chrono::seconds(extractIntParam(url, "expires"));

	// Update time
	mRegisterTime = extractUnsignedLongParam(url, "updatedAt");

	// CSeq
	mCSeq = extractIntParam(url, "cseq");

	// Alias
	mAlias = extractBoolParam(url, "alias");

	// Used as route
	mUsedAsRoute = extractBoolParam(url, "usedAsRoute");

	extractInfoFromHeader(url->url_headers);

	char transport[20] = {0};
	url_param(url[0].url_params, "transport", transport, sizeof(transport) - 1);

	url->url_headers = nullptr;

	if (temp_contact == nullptr) {
		mSipContact = sip_contact_create(mHome.home(), (url_string_t*)url, nullptr);
	} else {
		mSipContact = temp_contact;
	}
}

bool ExtendedContact::isSame(const ExtendedContact& otherContact) const {
	return mCallId == otherContact.mCallId && mKey == otherContact.mKey &&
	       url_cmp_all(mSipContact->m_url, otherContact.mSipContact->m_url) == 0;
	/* FIXME: the comparison is not complete */
}

} // namespace flexisip
