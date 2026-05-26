/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <stdexcept>
#include <string>
#include <string_view>

#include "sofia-sip/url.h"

#include "flexisip/flexisip-exception.hh"
#include "flexisip/sofia-wrapper/home.hh"

namespace sofiasip {

/**
 * Exception thrown while trying to create a new URL from
 * an invalid string or url_t.
 */
class InvalidUrlError : public flexisip::InvalidRequestError {
public:
	template <typename T, typename U>
	InvalidUrlError(T&& url, U&& reason) noexcept
	    : InvalidRequestError("Invalid SIP URI", url), _url(std::forward<T>(url)), _reason(std::forward<U>(reason)) {}

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

enum class TlsMode : uint8_t { NONE, FILES };
struct TlsConfigInfo {
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
	 * Create and initialize from URL type.
	 */
	explicit Url(url_type_e type);
	/**
	 * Create an URL by parsing a string.
	 * @exception InvalidUrlError Error while parsing the string.
	 * Scheme is set to its canonical form (lower cases)
	 */
	explicit Url(std::string_view);
	/**
	 * Create an URL from a SofiaSip's url_t structure.
	 * The url_t structure isn't modified and all the allocated
	 * string are duplicated.
	 * Scheme is set to its canonical form (lower cases)
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
	std::string_view getPort() const noexcept {
		return getUrlAttr(url_port);
	}
	/**
	 * @warning In case the port is empty, the URL is of "sip" or "sips" scheme type, and the host part is not an IP
	 * address, return an empty string.
	 * @return The port of the URL. If not set, return the default port for the URL scheme type.
	 */
	std::string_view getPortWithFallback() const noexcept {
		return url_port(_url);
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
	 * @brief Create a new URL by replacing the value of selected attribute by the given value.
	 *
	 * @param[in] attribute attribute whose value will be replaced
	 * @param[in] value     new value
	 *
	 * @throw UrlModificationError if the Url is empty
	 */
	Url replace(const char* url_t::* attribute, std::string_view value) const;
	/**
	 * Replace or insert a URI parameter.
	 */
	Url setParam(const std::string& name, const std::string& value) const;

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

	/**
	 * @note This function removes the parameter from the url.
	 *
	 * @param param name of the parameter to extract
	 * @return the extracted parameter or a default-constructed value of `Type` if not found or extraction failed
	 */
	template <typename Type>
	Type extractParam(const char* param);

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

private:
	// force the scheme in its canonical form: lower cases
	void canonizeScheme();
};

bool operator==(const TlsConfigInfo& lhs, const TlsConfigInfo& rhs);

inline std::ostream& operator<<(std::ostream& os, const sofiasip::Url& url) {
	return os << url.str();
}

template <>
std::string Url::extractParam<std::string>(const char* param);
template <>
int Url::extractParam<int>(const char* param);
template <>
uintptr_t Url::extractParam<uintptr_t>(const char* param);
template <>
time_t Url::extractParam<time_t>(const char* param);
template <>
bool Url::extractParam<bool>(const char* param);

} // namespace sofiasip
