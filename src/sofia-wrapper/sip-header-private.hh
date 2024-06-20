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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <cstdint>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string_view>

#include <sofia-sip/sip_header.h>
#include <sofia-sip/sip_protos.h>

#include "flexisip/flexisip-exception.hh"
#include "flexisip/sofia-wrapper/sip-header.hh"
#include "flexisip/utils/sip-uri.hh"

#include "sofia-wrapper/utilities.hh"
#include "utils/string-utils.hh"

namespace sofiasip {

/*
 * Safely get a string attribute from a pointer on a sofiasip struct.
 */
#define getStrAttribute(ptr, attribute) (ptr and ptr->attribute) ? ptr->attribute : ""
/*
 * Safely get an integer attribute from a pointer on a sofiasip struct.
 */
#define getIntAttribute(ptr, attribute) (ptr and ptr->attribute) ? ptr->attribute : 0

/*
 * Verify that a header string containing a SIP URI is well-formatted.
 */
inline bool isFormattedHeaderWithSipUri(const std::string& headerString) {
	return std::regex_match(headerString, std::regex{"(.*)<.+>(.*)"});
}

/**
 * Class that represent a request header.
 */
class SipHeaderRequest : public SipHeader {
public:
	/**
	 * Instantiate a request header.
	 * @param method The SIP method.
	 * @param requestURI The Request-URI.
	 */
	template <typename UriT>
	SipHeaderRequest(sip_method_t method, const UriT& requestURI) {
		setNativePtr(sip_request_create(mHome.home(), method, nullptr, toSofiaSipUrlUnion(requestURI), nullptr));
		if (mNativePtr == nullptr) {
			std::ostringstream err{};
			err << "cannot create request header (method: " << method << ", requestURI: " << requestURI << ")";
			throw flexisip::FlexisipException{err.str()};
		}
	}
	SipHeaderRequest(const SipHeaderRequest& src) : SipHeader{src} {
	}
	SipHeaderRequest(SipHeaderRequest&& src) : SipHeader{std::move(src)} {
	}
};

/**
 * Class that represents a From header.
 */
class SipHeaderFrom : public SipHeader {
public:
	/**
	 * Create a From header.
	 * @param fromURI The From-URI. May be a SipUri, a std::string or a raw string.
	 */
	template <typename UriT>
	SipHeaderFrom(const UriT& fromURI) {
		setNativePtr(sip_from_create(mHome.home(), toSofiaSipUrlUnion(fromURI)));
	}
	/**
	 * Create a From header with a Tag parameter.
	 * @param fromURI The From-URI. May be a SipUri, a std::string or a raw string.
	 * @param tag The tag value as string.
	 */
	template <typename UriT, typename StrT>
	SipHeaderFrom(const UriT& fromURI, const StrT& tag) : SipHeaderFrom{fromURI} {
		setTag(tag);
	}
	SipHeaderFrom(const SipHeaderFrom& src) : SipHeader(src) {
	}
	SipHeaderFrom(SipHeaderFrom&& src) : SipHeader(std::move(src)) {
	}

	/**
	 * Set the From-tag.
	 * @param tag The value of the tag as string, or nullptr to remove the tag parameter.
	 */
	void setTag(std::string_view tag) {
		sip_from_tag(mHome.home(), getSofiaPtr(), tag.data());
	}

private:
	sip_from_t* getSofiaPtr() noexcept {
		return reinterpret_cast<sip_from_t*>(mNativePtr);
	}
};

/**
 * Class that represents a To header.
 */
class SipHeaderTo : public SipHeader {
public:
	/**
	 * Create a To header.
	 * @param toURI The To-URI. May be a SipUri, a std::string or a raw string.
	 */
	template <typename UriT>
	SipHeaderTo(const UriT& toURI) {
		setNativePtr(sip_to_create(mHome.home(), toSofiaSipUrlUnion(toURI)));
	}
	SipHeaderTo(const SipHeaderTo& src) : SipHeader(src) {
	}
	SipHeaderTo(SipHeaderTo&& src) : SipHeader(std::move(src)) {
	}
};

/**
 * Class that represents a Path header.
 */
class SipHeaderPath : public SipHeader {
public:
	/**
	 * Create a Path header.
	 * @param pathURI The Path-URI.
	 */
	using SofiaType = sip_path_t;

	template <typename UriT>
	SipHeaderPath(const UriT& pathURI) {
		const auto str = toSofiaSipUrlUnion(pathURI)->us_str;
		if (!isFormattedHeaderWithSipUri(str))
			throw flexisip::FlexisipException{std::string("Invalid path header format: ") + str};
		setNativePtr(msg_header_make(mHome.home(), sip_path_class, str));
	}
	SipHeaderPath(const flexisip::SipUri& pathURI) {
		setNativePtr(sip_path_format(mHome.home(), "<%s>", pathURI.str().c_str()));
	}

	SipHeaderPath(const SipHeaderPath& src) : SipHeader(src) {
	}
	SipHeaderPath(SipHeaderPath&& src) : SipHeader(std::move(src)) {
	}

	const SofiaType* getSofiaPtr() const {
		return reinterpret_cast<SofiaType*>(mNativePtr);
	}
};

/**
 * Class that represents a vector of header of the same type.
 */
template <class Header>
class SipHeaderCollection {
public:
	SipHeaderCollection() = default;

	template <typename UriT>
	void add(const UriT& uri) {
		mCollection.emplace_back(uri);
	}

	void add(const Header& value) {
		mCollection.push_back(value);
	}
	void add(Header&& value) {
		mCollection.push_back(std::move(value));
	}

	const std::vector<Header>& getCollection() const {
		return mCollection;
	}

	auto* toSofiaType(su_home_t* home) const {
		using Type = typename Header::SofiaType;
		Type* sofiaPtr{};
		Type** ptr = &sofiaPtr;
		for (const auto& header : mCollection) {
			*ptr = reinterpret_cast<Type*>(msg_header_dup(home, header.getNativePtr()));
			ptr = &(*ptr)->r_next;
		}
		return sofiaPtr;
	}

private:
	std::vector<Header> mCollection;
};

/**
 * Class that represents a CallID header.
 */
class SipHeaderCallID : public SipHeader {
public:
	/**
	 * Create a CallID header without domain part.
	 * The CallID value is generated randomly.
	 */
	SipHeaderCallID() {
		setNativePtr(sip_call_id_create(mHome.home(), nullptr));
	}
	/**
	 * Create a CallID header with a given domain part.
	 * The CallID value is generated randomly and is formatted as '<random_value>@<domain>'.
	 */
	SipHeaderCallID(std::string_view domain) {
		setNativePtr(sip_call_id_create(mHome.home(), domain.data()));
	}
};

/**
 * Class that represents a CSeq header.
 */
class SipHeaderCSeq : public SipHeader {
public:
	/**
	 * Create a CSeq header.
	 * @param cseq The CSeq number.
	 * @param method The method.
	 */
	SipHeaderCSeq(std::uint32_t cseq, sip_method_t method) {
		setNativePtr(sip_cseq_create(mHome.home(), cseq, method, nullptr));
	}
};

/*
 * Represent a Contact header.
 */
class SipHeaderContact : public SipHeader {
public:
	using SofiaType = sip_contact_t;

	/**
	 * Create a Contact header.
	 * @param uri The contact URI.
	 */
	template <typename UriT>
	explicit SipHeaderContact(const UriT& uri) : SipHeaderContact{uri, nullptr} {
	}

	explicit SipHeaderContact(const flexisip::SipUri& uri) {
		setNativePtr(sip_contact_create(mHome.home(), toSofiaSipUrlUnion(uri), nullptr));
	}

	/**
	 * Create a Contact header.
	 * @param uri The contact URI or well-formatted SIP header containing a SIP URI.
	 * @param params List of header parameters.
	 */
	template <typename UriT, typename... Args>
	explicit SipHeaderContact(const UriT& uri, Args... params) {
		const auto sofiasipUrl = toSofiaSipUrlUnion(uri);
		if (isFormattedHeaderWithSipUri(sofiasipUrl->us_str)) {
			setNativePtr(sip_contact_make(mHome.home(), sofiasipUrl->us_str));
			return;
		}
		setNativePtr(sip_contact_create(mHome.home(), sofiasipUrl, std::forward<Args>(params)..., nullptr));
	}

	std::string_view getDisplayName() const {
		return getStrAttribute(getSofiaPtr(), m_display);
	}
	flexisip::SipUri getUri() const {
		return getSofiaPtr() ? flexisip::SipUri{getSofiaPtr()->m_url} : flexisip::SipUri{};
	}
	std::vector<SipMsgParam> getParams() const {
		const auto* sofiaPtr = getSofiaPtr();
		if (sofiaPtr == nullptr) return {};

		std::vector<SipMsgParam> params{};
		const int nbParams = static_cast<int>(msg_params_length(sofiaPtr->m_params));
		for (int paramId = 0; paramId < nbParams; ++paramId) {
			params.emplace_back(sofiaPtr->m_params[paramId]);
		}
		return params;
	}
	std::string_view getComment() const {
		return getStrAttribute(getSofiaPtr(), m_comment);
	}
	std::string_view getQ() const {
		return getStrAttribute(getSofiaPtr(), m_q);
	}
	std::string_view getExpires() const {
		return getStrAttribute(getSofiaPtr(), m_expires);
	}

private:
	SofiaType* getSofiaPtr() const {
		return reinterpret_cast<SofiaType*>(mNativePtr);
	}
};

/*
 * Represent an Expires header.
 */
class SipHeaderExpires : public SipHeader {
public:
	using SofiaType = sip_expires_t;

	/**
	 * Create an Expires header.
	 * @param value Expire value.
	 *
	 * @throw flexisip::FlexisipException if expire value is not positive.
	 */
	explicit SipHeaderExpires(const int value) {
		if (value < 0) throw flexisip::FlexisipException{"expire value must be positive"};

		setNativePtr(sip_expires_create(mHome.home(), value));
	}

	/*
	 * Get expire date: seconds since Jan 1, 1900.
	 */
	sip_time_t getDate() const {
		return getIntAttribute(getSofiaPtr(), ex_date);
	}
	/*
	 * Get delta seconds.
	 */
	sip_time_t getDelta() const {
		return getIntAttribute(getSofiaPtr(), ex_delta);
	}

private:
	SofiaType* getSofiaPtr() const {
		return reinterpret_cast<SofiaType*>(mNativePtr);
	}
};

/**
 * Class that represents a User-Agent header.
 */
class SipHeaderUserAgent : public SipHeader {
public:
	/**
	 * Create a User-Agent header.
	 * @param ua The User-Agent string.
	 */
	SipHeaderUserAgent(std::string_view ua) {
		setNativePtr(sip_user_agent_make(mHome.home(), ua.data()));
	}
};

/**
 * Class that represents a custom (a.k.a "unknown") header.
 */
class SipCustomHeader : public SipHeader {
public:
	/**
	 * Create a custom header.
	 * @param name The name of the custom header.
	 * @param value The value of the custom header.
	 */
	SipCustomHeader(std::string_view name, std::string_view value) {
		setNativePtr(sip_unknown_format(mHome.home(), "%s: %s", name.data(), value.data()));
	}

	SipCustomHeader(const SipCustomHeader&) = default;
	SipCustomHeader(SipCustomHeader&&) = default;
};

} // namespace sofiasip