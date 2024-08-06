/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "sofia-sip/sdp.h"

#include <memory>
#include <string_view>
#include <variant>

namespace sofiasip {

/** The error message associated with an SDP parser */
class SdpParsingError : public std::string_view {
public:
	friend std::ostream& operator<<(std::ostream&, const SdpParsingError&);
};

/** SDP session or media attribute
 *  ("a=" line)
 */
class SdpAttribute : private ::sdp_attribute_t {
public:
	static SdpAttribute* wrap(::sdp_attribute_t*);
	std::string_view name() const {
		return a_name;
	}

	std::string_view value() const {
		return a_value;
	}
};

/**
 * An abstraction to iterate over all members of a linked-list of ::sdp_attribute_t that match a given name
 *
 * This class is iterable.
 */
class SdpMediaAttributeFilter {
public:
	class Iterator {
	public:
		explicit Iterator(::sdp_attribute_t* ptr, const char* name);
		Iterator& operator++();
		bool operator!=(const Iterator& other) const {
			return mPtr != other.mPtr;
		}
		SdpAttribute& operator*() {
			return *SdpAttribute::wrap(mPtr);
		}

	private:
		const char* const mName;
		::sdp_attribute_t* mPtr;
	};

	explicit SdpMediaAttributeFilter(::sdp_attribute_t* head, const char* name) : mHead(head), mName(name) {
	}

	Iterator begin() {
		return Iterator(mHead, mName);
	}
	Iterator end() {
		return Iterator(nullptr, mName);
	}
	[[deprecated("TODO")]] Iterator begin() const;
	[[deprecated("TODO")]] Iterator end() const;

private:
	::sdp_attribute_t* mHead;
	const char* const mName;
};

/**
 * An abstraction to iterate over a linked-list of ::sdp_attribute_t
 *
 * This class is iterable.
 */
class SdpMediaAttributeList {
public:
	class [[deprecated("TODO")]] Iterator;

	explicit SdpMediaAttributeList(::sdp_attribute_t* head) : mHead(head){};

	/** Find attributes matching given name. */
	SdpMediaAttributeFilter find(const char* name) {
		return SdpMediaAttributeFilter(mHead, name);
	}

	[[deprecated("TODO")]] Iterator begin() const;
	[[deprecated("TODO")]] Iterator end() const;

private:
	::sdp_attribute_t* mHead;
};

/** Media announcement.
 *  ("m=" line)
 *
 * This structure describes one media type, e.g., audio.  The description
 * contains the transport address (IP address and port) used for the group,
 * the transport protocol used, the media formats or RTP payload types, and
 * optionally media-specific bandwidth specification, encryption key and
 * attributes.
 *
 * There is a pointer (m_user) for the application data, too.
 */
class SdpMedia : private ::sdp_media_t {
public:
	static SdpMedia* wrap(::sdp_media_t*);

	SdpMediaAttributeList attributes() {
		return SdpMediaAttributeList(m_attributes);
	}

	[[deprecated("TODO")]] sdp_session_t* m_session();        /**< Back-pointer to session level */
	[[deprecated("TODO")]] sdp_media_e m_type();              /**< Media type  */
	[[deprecated("TODO")]] sdp_text_t* m_type_name();         /**< Media type name */
	[[deprecated("TODO")]] unsigned long m_port();            /**< Transport port number */
	[[deprecated("TODO")]] unsigned long m_number_of_ports(); /**< Number of ports (if multiple) */
	[[deprecated("TODO")]] sdp_proto_e m_proto();             /**< Transport protocol  */
	[[deprecated("TODO")]] sdp_text_t* m_proto_name();        /**< Transport protocol name */
	[[deprecated("TODO")]] sdp_list_t* m_format();            /**< List of media formats */
	[[deprecated("TODO")]] sdp_rtpmap_t* m_rtpmaps();         /**< List of RTP maps */
	[[deprecated("TODO")]] sdp_text_t* m_information();       /**< Media information */
	[[deprecated("TODO")]] sdp_connection_t* m_connections(); /**< List of addresses used */
	[[deprecated("TODO")]] sdp_bandwidth_t* m_bandwidths();   /**< Bandwidth specification */
	[[deprecated("TODO")]] sdp_key_t* m_key();                /**< Media key */
	[[deprecated("TODO")]] void* m_user();                    /**< User data. */
	/** Rejected media */
	[[deprecated("TODO")]] unsigned m_rejected();
	/** Inactive, recvonly, sendonly, sendrecv */
	[[deprecated("TODO")]] ::sdp_mode_t m_mode();
};

/**
 * An abstraction to iterate over a linked-list of ::sdp_media_t
 *
 * This class is iterable.
 */
class SdpMediaList {
public:
	class Iterator {
	public:
		explicit Iterator(::sdp_media_t* ptr) : mPtr(ptr) {
		}
		Iterator& operator++() {
			mPtr = mPtr->m_next;
			return *this;
		}
		bool operator!=(const Iterator& other) const {
			return mPtr != other.mPtr;
		}
		SdpMedia& operator*() {
			return *SdpMedia::wrap(mPtr);
		}

	private:
		::sdp_media_t* mPtr;
	};

	explicit SdpMediaList(::sdp_media_t* head) : mHead(head) {
	}

	Iterator begin() {
		return Iterator(mHead);
	}
	Iterator end() {
		return Iterator(nullptr);
	}
	[[deprecated("TODO")]] Iterator begin() const;
	[[deprecated("TODO")]] Iterator end() const;

private:
	::sdp_media_t* mHead;
};

/**
 * SDP session description
 *
 * Created by `SdpParser`
 */
class SdpSession : private ::sdp_session_t {
public:
	static SdpSession* wrap(::sdp_session_t*);

	// Media descriptors
	SdpMediaList medias();

	[[deprecated("TODO")]] sdp_version_t* sdp_version();       /**< SDP version */
	[[deprecated("TODO")]] sdp_origin_t* sdp_origin();         /**< Owner/creator and session ID */
	[[deprecated("TODO")]] sdp_text_t* sdp_subject();          /**< Session name */
	[[deprecated("TODO")]] sdp_text_t* sdp_information();      /**< Session information  */
	[[deprecated("TODO")]] sdp_text_t* sdp_uri();              /**< URi of description */
	[[deprecated("TODO")]] sdp_list_t* sdp_emails();           /**< E-mail address(s) */
	[[deprecated("TODO")]] sdp_list_t* sdp_phones();           /**< Phone number(s)  */
	[[deprecated("TODO")]] sdp_connection_t* sdp_connection(); /**< Group (or member) address */
	[[deprecated("TODO")]] sdp_bandwidth_t* sdp_bandwidths();  /**< Session bandwidth */
	[[deprecated("TODO")]] sdp_time_t* sdp_time();             /**< Session active time */
	[[deprecated("TODO")]] sdp_key_t* sdp_key();               /**< Session key */
	[[deprecated("TODO")]] sdp_attribute_t* sdp_attributes();  /**< Session attributes */
	[[deprecated("TODO")]] sdp_text_t* sdp_charset();          /**< SDP charset (default is UTF8) */
};

/**
 * A thin wrapper for SofiaSip's `sdp_parser` type.
 */
class SdpParser {
public:
	struct Deleter {
		void operator()(SdpParser*) noexcept;
	};
	using UniquePtr = std::unique_ptr<SdpParser, Deleter>;

	enum class Flags : int {
		None = 0,
		Strict = ::sdp_parse_flags_e::sdp_f_strict,

		__TheRest [[deprecated("TODO: Add flags supported by sdp_parse")]],
	};

	// Create a new stand-alone SdpParser
	static UniquePtr parse(std::string_view msg, Flags flags = Flags::None);
	// Create a new SdpParser managed by a su_home_t
	static SdpParser& parse(su_home_t&, std::string_view msg, Flags flags = Flags::None);

	// Prevent creating instances of this class.
	// Only references will be obtained via `reinterpret_cast`ing
	SdpParser() = delete;
	SdpParser(const SdpParser&) = delete;
	SdpParser& operator=(const SdpParser&) = delete;
	~SdpParser() = delete;

	/** Retrieve an SDP session structure.
	 *
	 * @return
	 *   Returns a reference to a parsed SDP message or, if an error has occurred, a string description of the error.
	 *   The reference and all the data in the structure are valid until the SdpParser is destructed.
	 */
	std::variant<std::reference_wrapper<SdpSession>, SdpParsingError> session();

	[[deprecated("To be wrapped")]] int sdp_sanity_check();
	[[deprecated("To be wrapped")]] su_home_t* sdp_parser_home();

private:
	// Bare wrapper to `sdp_parse`
	static SdpParser* parse(su_home_t*, std::string_view msg, Flags flags);

	// Retrieve the raw sofia pointer
	::sdp_parser toSofia();
};

} // namespace sofiasip
