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

/**
 * SDP session or media attribute
 * ("a=" line)
 */
class SdpAttribute : private ::sdp_attribute_t {
public:
	/**
	 * An SDP attribute is just a bunch of pointers.
	 * The default copy constructor will be shallow and (very) unsafe.
	 * If you need a copy, write a dedicated function and think it through.
	 */
	SdpAttribute(const SdpAttribute&) = delete;

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

private:
	::sdp_attribute_t* mHead;
	const char* const mName;
};

/**
 * An abstraction to access a linked-list of ::sdp_attribute_t
 */
class SdpMediaAttributeList {
public:
	explicit SdpMediaAttributeList(::sdp_attribute_t* head) : mHead(head){};

	/** Find attributes matching given name. */
	SdpMediaAttributeFilter find(const char* name) {
		return SdpMediaAttributeFilter(mHead, name);
	}

private:
	::sdp_attribute_t* mHead;
};

/**
 * SDP connection - host or group address.
 * ("c=" line)
 *
 * Some getters and setters are not yet implemented. They may be added later.
 */
class SdpConnection : private ::sdp_connection_t {
public:
	/**
	 * An SDP connection is just a bunch of pointers.
	 * The default copy constructor will be shallow and (very) unsafe.
	 * If you need a copy, write a dedicated function and think it through.
	 */
	SdpConnection(const SdpConnection&) = delete;

	static SdpConnection* wrap(::sdp_connection_t*);

	// Host or group address
	std::string_view address() const {
		return c_address;
	}
};

/**
 * An abstraction to iterate over a linked-list of ::sdp_connection_t.
 *
 * This class is iterable.
 */
class SdpConnectionList {
public:
	class Iterator {
	public:
		explicit Iterator(::sdp_connection_t* ptr) : mPtr(ptr) {
		}
		Iterator& operator++() {
			mPtr = mPtr->c_next;
			return *this;
		}
		bool operator!=(const Iterator& other) const {
			return mPtr != other.mPtr;
		}
		SdpConnection& operator*() {
			return *SdpConnection::wrap(mPtr);
		}

	private:
		::sdp_connection_t* mPtr;
	};

	explicit SdpConnectionList(::sdp_connection_t* head) : mHead(head) {
	}

	Iterator begin() {
		return Iterator(mHead);
	}
	Iterator end() {
		return Iterator(nullptr);
	}

private:
	::sdp_connection_t* mHead;
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
 *
 * Some getters and setters are not yet implemented. They may be added later.
 */
class SdpMedia : private ::sdp_media_t {
public:
	/**
	 * An SDP media is just a bunch of pointers.
	 * The default copy constructor will be shallow and (very) unsafe.
	 * If you need a copy, write a dedicated function and think it through.
	 */
	SdpMedia(const SdpMedia&) = delete;

	static SdpMedia* wrap(::sdp_media_t*);

	// Media attributes
	SdpMediaAttributeList attributes() {
		return SdpMediaAttributeList(m_attributes);
	}
	// List of addresses used
	SdpConnectionList connections() {
		return SdpConnectionList(m_connections);
	}
	// Media type name
	std::string_view typeName() const {
		return m_type_name;
	}
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

private:
	::sdp_media_t* mHead;
};

/**
 * SDP session description
 *
 * Created by `SdpParser`
 *
 * Some getters and setters are not yet implemented. They may be added later.
 */
class SdpSession : private ::sdp_session_t {
public:
	/**
	 * An SDP session is just a bunch of pointers.
	 * The default copy constructor will be shallow and (very) unsafe.
	 * If you need a copy, write a dedicated function and think it through.
	 */
	SdpSession(const SdpSession&) = delete;

	static SdpSession* wrap(::sdp_session_t*);

	// Media descriptors
	SdpMediaList medias();
	// Group (or member) address
	SdpConnection& connection();
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

	// The flags list is not exhaustive. The other flags supported by sdp_parse may be added later.
	enum class Flags : int {
		None = 0,
		Strict = ::sdp_parse_flags_e::sdp_f_strict,
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

private:
	// Bare wrapper to `sdp_parse`
	static SdpParser* parse(su_home_t*, std::string_view msg, Flags flags);

	// Retrieve the raw sofia pointer
	::sdp_parser toSofia();
};

} // namespace sofiasip