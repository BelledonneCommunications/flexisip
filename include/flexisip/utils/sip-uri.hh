/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

#include <bctoolbox/ownership.hh>

#include <sofia-sip/sip.h>
#include <sofia-sip/url.h>

#include "flexisip/sofia-wrapper/home.hh"

namespace sofiasip {

/**
 * Exception thrown while trying to create a new URL from
 * an invalid string or url_t.
 */
class InvalidUrlError : public std::invalid_argument {
public:
	template <typename T, typename U>
	InvalidUrlError(T&& url, U&& reason) noexcept
	    : invalid_argument(url), _url(std::forward<T>(url)), _reason(std::forward<U>(reason)) {
	}

	/**
	 * Get the string that couldn't be parsed.
	 */
	const std::string& getUrl() const noexcept {
		return _url;
	}
	/**
	 * Get the reason of the parsing failure.
	 */
	const std::string& getReason() const noexcept {
		return _reason;
	}

private:
	std::string _url;
	std::string _reason;
};

/**
 * Exception thrown when an URL couldn't be modified.
 */
class UrlModificationError : public std::logic_error {
public:
	using logic_error::logic_error;
};

enum class TlsMode : uint8_t { NONE, OLD, NEW };
struct TlsConfigInfo {
	std::string certifDir{};
	std::string certifFile{};
	std::string certifPrivateKey{};
	std::string certifCaFile{};
	TlsMode mode = TlsMode::NONE;
};

/**
 * Wrapper for SofiaSip's URLs.
 */
class Url {
public:
	/**
	 * Create an empty URL.
	 */
	Url() = default;
	/**
	 * Create an URL by parsing a string.
	 * @exception InvalidUrlError Error while parsing the string.
	 */
	explicit Url(std::string_view);
	/**
	 * Create an URL from a SofiaSip's url_t structure.
	 * The url_t structure isn't modified and all the allocated
	 * string are duplicated.
	 */
	explicit Url(const url_t* src) noexcept;
	Url(const Url& src) noexcept;
	/**
	 * Move constructor.
	 * @note src become an empty URL after the process.
	 */
	Url(Url&& src) noexcept;
	virtual ~Url() = default;

	Url& operator=(const Url& src) noexcept;
	/**
	 * Move assign operator.
	 * @note src become an empty URL after the process.
	 */
	Url& operator=(Url&& src) noexcept;

	/**
	 * Test whether the URL is empty.
	 */
	bool empty() const noexcept {
		return _url == nullptr;
	}

	/**
	 * Return a pointer on the underlying sip_t structure.
	 */
	const url_t* get() const noexcept {
		return _url;
	}
	/**
	 * Format the URL as string.
	 * @note The result of formatting is cached.
	 */
	const std::string& str() const noexcept;
	/**
	 * Returns the type of the URL as url_type_e enum.
	 * @return Returns any value of url_type_e if non-empty,
	 * _url_none otherwise.
	 */
	url_type_e getType() const noexcept {
		return _url ? static_cast<url_type_e>(_url->url_type) : _url_none;
	}

#define getUrlAttr(attr) _url && _url->attr ? _url->attr : ""
	std::string getScheme() const noexcept {
		return getUrlAttr(url_scheme);
	}
	std::string getUser() const noexcept {
		return getUrlAttr(url_user);
	}
	std::string getPassword() const noexcept {
		return getUrlAttr(url_password);
	}
	std::string getHost() const noexcept {
		return getUrlAttr(url_host);
	}
	std::string getPort(bool usingFallback = false) const noexcept {
		return usingFallback ? url_port(_url) : getUrlAttr(url_port);
	}
	std::string getPath() const noexcept {
		return getUrlAttr(url_path);
	}
	std::string getParams() const noexcept {
		return getUrlAttr(url_params);
	}
	std::string getHeaders() const noexcept {
		return getUrlAttr(url_headers);
	}
	std::string getFragment() const noexcept {
		return getUrlAttr(url_fragment);
	}
#undef getUrlAttr

	/**
	 * Create a new URL by replacing the user past by another string.
	 * @throw UrlModificationError when the actual URL is empty or
	 * the new URL would be invalid.
	 */
	Url replaceUser(const std::string& newUser) const;

	/**
	 * Test whether the URL has a given param by its name.
	 */
	bool hasParam(const std::string& name) const noexcept {
		return hasParam(name.c_str());
	}
	bool hasParam(const char* name) const noexcept {
		return url_has_param(_url, name);
	}

	std::string getParam(const std::string& paramName) const;
	bool getBoolParam(const std::string& paramName, bool defaultValue) const;

	void removeParam(const std::string& paramName);

	TlsConfigInfo getTlsConfigInfo() const;

	/**
	 * Strictly compare all the components of the URL
	 */
	bool compareAll(const Url& other) const;

protected:
	mutable Home _home;
	url_t* _url = nullptr;
	mutable std::string _urlAsStr;
};

bool operator==(const TlsConfigInfo& lhs, const TlsConfigInfo& rhs);
} // namespace sofiasip

inline std::ostream& operator<<(std::ostream& os, const sofiasip::Url& url) {
	return os << url.str();
}

namespace flexisip {

/**
 * A specialisation of sofiasip::Url which ensures that the URL is a
 * SIP or SIPS URI.
 */
class SipUri : public sofiasip::Url {
public:
	class Params {
	public:
		Params(const char* c);

		bool operator==(const Params& other) const;
		bool operator!=(const Params& other) const {
			return !(*this == other);
		}

	private:
		std::unordered_map<std::string, std::string> mParams{};
	};

	class Headers {
	public:
		Headers(const char* c);

		bool operator==(const Headers& other) const;
		bool operator!=(const Headers& other) const {
			return !(*this == other);
		}

	private:
		std::unordered_map<std::string, std::string> mHeaders{};
	};

	SipUri() = default;
	/**
	 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
	 */
	explicit SipUri(std::string_view);
	/**
	 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
	 */
	explicit SipUri(const url_t* src);
	/**
	 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
	 */
	explicit SipUri(const sofiasip::Url& src);
	/**
	 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
	 */
	explicit SipUri(sofiasip::Url&& src);
	SipUri(const SipUri& src) noexcept = default;
	SipUri(SipUri&& src) noexcept = default;
	~SipUri() override = default;

	SipUri& operator=(const SipUri& src) noexcept = default;
	SipUri& operator=(SipUri&& src) noexcept = default;

	/**
	 * @throw sofiasip::UrlModificationError if the URL is empty or
	 * the result would be an invalid SIP URI.
	 */
	SipUri replaceUser(const std::string& newUser) const;

	/**
	 * True if this URI is the same as the other according to RFC 3261.
	 * https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.4
	 */
	bool rfc3261Compare(const url_t* other) const;
	bool rfc3261Compare(const SipUri& other) const {
		return rfc3261Compare(other._url);
	}

private:
	static void checkUrl(const sofiasip::Url& url);
};

// Enable to check validity of a sip uri raw url (use SipUri rather than raw url whenever possible)
bool isValidSipUri(const url_t* url);

} // namespace flexisip
