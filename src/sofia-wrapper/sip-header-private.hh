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
 * Represent a Request header.
 */
class SipHeaderRequest : public SipHeader {
public:
	using SofiaType = sip_request_t;

	/**
	 * Create a Request header.
	 * @param method the SIP method
	 * @param requestURI SIP URI (may be a flexisip::SipUri, an std::string or a raw string)
	 *
	 * @throw flexisip::FlexisipException on creation failure
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

	SipHeaderRequest(const SipHeaderRequest& src) = default;
	SipHeaderRequest(SipHeaderRequest&& src) = default;
};

/**
 * Represent a From header.
 */
class SipHeaderFrom : public SipHeader {
public:
	using SofiaType = sip_from_t;

	/**
	 * Create a From header.
	 * @param fromURI SIP URI (may be a flexisip::SipUri, an std::string or a raw string)
	 */
	template <typename UriT>
	SipHeaderFrom(const UriT& fromURI) {
		setNativePtr(sip_from_create(mHome.home(), toSofiaSipUrlUnion(fromURI)));
	}

	/**
	 * Create a From header with a Tag parameter.
	 * @param fromURI SIP URI (may be a flexisip::SipUri, an std::string or a raw string)
	 * @param tag tag value
	 */
	template <typename UriT, typename StrT>
	SipHeaderFrom(const UriT& fromURI, const StrT& tag) : SipHeaderFrom{fromURI} {
		setTag(tag);
	}

	SipHeaderFrom(const SipHeaderFrom& src) = default;
	SipHeaderFrom(SipHeaderFrom&& src) = default;

	/**
	 * Set the tag value.
	 * @param tag the tag value, or nullptr to remove the tag parameter
	 */
	void setTag(std::string_view tag) {
		sip_from_tag(mHome.home(), reinterpret_cast<SofiaType*>(mNativePtr), tag.data());
	}
};

/**
 * Represent a To header.
 */
class SipHeaderTo : public SipHeader {
public:
	using SofiaType = sip_to_t;

	/**
	 * Create a To header.
	 * @param toURI SIP URI (may be a flexisip::SipUri, an std::string or a raw string)
	 */
	template <typename UriT>
	SipHeaderTo(const UriT& toURI) {
		setNativePtr(sip_to_create(mHome.home(), toSofiaSipUrlUnion(toURI)));
	}

	SipHeaderTo(const SipHeaderTo& src) = default;
	SipHeaderTo(SipHeaderTo&& src) = default;
};

/**
 * Represent a Path header.
 */
class SipHeaderPath : public SipHeader {
public:
	using SofiaType = sip_path_t;

	/**
	 * Create a Path header.
	 * @param pathURI SIP URI (may be a flexisip::SipUri, an std::string or a raw string)
	 */
	template <typename UriT>
	SipHeaderPath(const UriT& pathURI) {
		const auto str = toSofiaSipUrlUnion(pathURI)->us_str;
		if (!isFormattedHeaderWithSipUri(str))
			throw flexisip::FlexisipException{std::string{"invalid path header format ("} + str + std::string{")"}};
		setNativePtr(msg_header_make(mHome.home(), sip_path_class, str));
	}

	/**
	 * Create a Path header.
	 * @param pathURI SIP URI
	 */
	SipHeaderPath(const flexisip::SipUri& pathURI) {
		setNativePtr(sip_path_format(mHome.home(), "<%s>", pathURI.str().c_str()));
	}

	SipHeaderPath(const SipHeaderPath& src) = default;
	SipHeaderPath(SipHeaderPath&& src) = default;
};

/**
 * Represent a Route header.
 */
class SipHeaderRoute : public SipHeader {
public:
	using SofiaType = sip_route_t;

	/**
	 * Create a Route header.
	 * @param uri SIP URI (may be a flexisip::SipUri, an std::string or a raw string) or well-formatted SIP header
	 * containing a SIP URI
	 * @param maddr route header parameter 'maddr', ignored if @param uri is already a well-formatted header
	 *
	 * @note Example of a well-formatted header: "<sip:sip.example.org;transport=tcp;lr>"
	 */
	template <typename UriT>
	SipHeaderRoute(const UriT& uri, const UriT& maddr = UriT{}) {
		const auto* sofiasipUrl = toSofiaSipUrlUnion(uri);
		if (isFormattedHeaderWithSipUri(sofiasipUrl->us_str)) {
			setNativePtr(sip_route_make(mHome.home(), sofiasipUrl->us_str));
			return;
		}
		setNativePtr(sip_route_create(mHome.home(), sofiasipUrl->us_url, toSofiaSipUrlUnion(maddr)->us_url));
	}

	SipHeaderRoute(const SipHeaderRoute& src) = default;
	SipHeaderRoute(SipHeaderRoute&& src) = default;

	std::string_view getDisplayName() const {
		return getStrAttribute(reinterpret_cast<SofiaType*>(mNativePtr), r_display);
	}

	const url_t& getUrl() const {
		return reinterpret_cast<SofiaType*>(mNativePtr)->r_url[0];
	}
};

/**
 * Represent a vector of non-empty headers of the same type.
 */
template <class Header>
class SipHeaderCollection {
public:
	SipHeaderCollection() = default;

	template <typename UriT>
	void add(const UriT& uri) {
		add(Header{uri});
	}

	// Collect only initialized headers.
	void add(const Header& value) {
		if (value.getNativePtr()) mCollection.push_back(value);
	}

	void add(Header&& value) {
		if (value.getNativePtr()) mCollection.push_back(std::move(value));
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
 * Represent a CallID header.
 */
class SipHeaderCallID : public SipHeader {
public:
	/**
	 * Create a CallID header without domain part.
	 * @note: the CallID value is generated randomly
	 */
	SipHeaderCallID() {
		setNativePtr(sip_call_id_create(mHome.home(), nullptr));
	}

	/**
	 * Create a CallID header with a given domain part.
	 * @note: the CallID value is generated randomly and is formatted as '<random_value>@<domain>'
	 */
	SipHeaderCallID(std::string_view domain) {
		setNativePtr(sip_call_id_create(mHome.home(), domain.data()));
	}
};

/**
 * Represent a CSeq header.
 */
class SipHeaderCSeq : public SipHeader {
public:
	/**
	 * Create a CSeq header.
	 * @param cseq CSeq value
	 * @param method the method
	 */
	SipHeaderCSeq(std::uint32_t cseq, sip_method_t method) {
		setNativePtr(sip_cseq_create(mHome.home(), cseq, method, nullptr));
	}
};

/**
 * Represent a Max-Forwards header.
 */
class SipHeaderMaxForwards : public SipHeader {
public:
	/**
	 * Create a Max-Forwards header.
	 * @param maxForwards max forwards value
	 */
	SipHeaderMaxForwards(unsigned long maxForwards) {
		setNativePtr(sip_max_forwards_make(mHome.home(), std::to_string(maxForwards).c_str()));
	}

	unsigned long getCount() const {
		return getIntAttribute(reinterpret_cast<sip_max_forwards_t*>(mNativePtr), mf_count);
	}
};

/**
 * Represent a Contact header.
 */
class SipHeaderContact : public SipHeader {
public:
	using SofiaType = sip_contact_t;

	/**
	 * Create a Contact header.
	 * @param uri SIP URI (may be a flexisip::SipUri, an std::string or a raw string) or well-formatted SIP header
	 * containing a SIP URI.
	 * @param params List of header parameters. Ignored if @param uri is already a well-formatted header.
	 *
	 * @note Example of a well-formatted header: "Display Name <sip:contact@host:port;transport=tcp>;expires=0"
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

	/**
	 * Create a Contact header.
	 * @param uri SIP URI (may be a flexisip::SipUri, an std::string or a raw string) or well-formatted SIP header
	 * containing a SIP URI.
	 *
	 * @note Example of a well-formatted header: "Display Name <sip:contact@host:port;transport=tcp>;expires=0"
	 */
	template <typename UriT>
	explicit SipHeaderContact(const UriT& uri) : SipHeaderContact{uri, nullptr} {
	}

	/**
	 * Create a Contact header.
	 * @param uri SIP URI
	 */
	explicit SipHeaderContact(const flexisip::SipUri& uri) {
		setNativePtr(sip_contact_create(mHome.home(), toSofiaSipUrlUnion(uri), nullptr));
	}

	std::string_view getDisplayName() const {
		return getStrAttribute(reinterpret_cast<SofiaType*>(mNativePtr), m_display);
	}

	flexisip::SipUri getUri() const {
		return mNativePtr ? flexisip::SipUri{reinterpret_cast<SofiaType*>(mNativePtr)->m_url} : flexisip::SipUri{};
	}

	std::vector<SipMsgParam> getParams() const {
		const auto* sofiaPtr = reinterpret_cast<SofiaType*>(mNativePtr);
		if (sofiaPtr == nullptr) return {};

		std::vector<SipMsgParam> params{};
		const int nbParams = static_cast<int>(msg_params_length(sofiaPtr->m_params));
		for (int paramId = 0; paramId < nbParams; ++paramId) {
			params.emplace_back(sofiaPtr->m_params[paramId]);
		}
		return params;
	}

	std::string_view getComment() const {
		return getStrAttribute(reinterpret_cast<SofiaType*>(mNativePtr), m_comment);
	}

	std::string_view getQ() const {
		return getStrAttribute(reinterpret_cast<SofiaType*>(mNativePtr), m_q);
	}

	std::string_view getExpires() const {
		return getStrAttribute(reinterpret_cast<SofiaType*>(mNativePtr), m_expires);
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
	 * @param value expire value
	 *
	 * @throw flexisip::FlexisipException if expire value is negative or null
	 */
	explicit SipHeaderExpires(const int value) {
		if (value < 0) throw flexisip::FlexisipException{"expire value must be positive"};
		setNativePtr(sip_expires_create(mHome.home(), value));
	}

	/*
	 * Get expire date: seconds since Jan 1, 1900.
	 */
	sip_time_t getDate() const {
		return getIntAttribute(reinterpret_cast<SofiaType*>(mNativePtr), ex_date);
	}
	/*
	 * Get delta seconds.
	 */
	sip_time_t getDelta() const {
		return getIntAttribute(reinterpret_cast<SofiaType*>(mNativePtr), ex_delta);
	}
};

/**
 * Represent a User-Agent header.
 */
class SipHeaderUserAgent : public SipHeader {
public:
	/**
	 * Create a User-Agent header.
	 * @param ua user-agent value
	 */
	SipHeaderUserAgent(std::string_view ua) {
		setNativePtr(sip_user_agent_make(mHome.home(), ua.data()));
	}
};

/*
 * Represent an Event header.
 */
class SipHeaderEvent : public SipHeader {
public:
	using SofiaType = sip_event_t;

	/**
	 * Create an Event header.
	 * @param event the event value
	 */
	SipHeaderEvent(std::string_view event) {
		setNativePtr(sip_event_make(mHome.home(), event.data()));
	}

	std::string_view getType() const {
		return getStrAttribute(reinterpret_cast<SofiaType*>(mNativePtr), o_type);
	}
};

/**
 * Represent a Custom header (a.k.a "Unknown") header.
 */
class SipCustomHeader : public SipHeader {
public:
	/**
	 * Create a custom header.
	 * @param name the name of the custom header
	 * @param value the value of the custom header
	 *
	 * @note this will produce an header with the following format: "name: value"
	 */
	SipCustomHeader(std::string_view name, std::string_view value) {
		setNativePtr(sip_unknown_format(mHome.home(), "%s: %s", name.data(), value.data()));
	}

	SipCustomHeader(const SipCustomHeader&) = default;
	SipCustomHeader(SipCustomHeader&&) = default;
};

} // namespace sofiasip