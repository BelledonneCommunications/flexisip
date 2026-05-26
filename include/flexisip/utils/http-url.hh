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

#include <optional>

#include "flexisip/sofia-wrapper/url.hh"

namespace flexisip {

/**
 * A specialization of sofiasip::Url that ensures that the URL is an HTTP or HTTPS URL.
 */
class HttpUrl : public sofiasip::Url {
public:
	enum class Scheme : std::underlying_type_t<url_type_e> {
		invalid = url_invalid,
		http = url_http,
		https = url_https,
		none = _url_none,
	};

	HttpUrl() = default;
	explicit HttpUrl(std::string_view str);
	explicit HttpUrl(const url_t* src);
	explicit HttpUrl(const sofiasip::Url& src);
	explicit HttpUrl(sofiasip::Url&& src);

	HttpUrl(const HttpUrl& src) noexcept = default;
	HttpUrl(HttpUrl&& src) noexcept = default;
	~HttpUrl() override = default;

	HttpUrl& operator=(const HttpUrl& src) noexcept = default;
	HttpUrl& operator=(HttpUrl&& src) noexcept = default;

	Scheme getSchemeType() const noexcept;

	/**
	 * Replace the URL path.
	 *
	 * The provided path can contain leading/trailing slashes. It will be normalized
	 * before being stored in the underlying Sofia-SIP URL.
	 */
	[[nodiscard]] HttpUrl replacePath(std::string_view path) const;

	/**
	 * Append a path fragment to the current URL path.
	 *
	 * Both the current path and the provided path fragment are normalized, so:
	 * "api/" + "/v1//push" becomes "api/v1/push".
	 */
	[[nodiscard]] HttpUrl appendPath(std::string_view path) const;

	/**
	 * Return the path as expected by HTTP requests.
	 *
	 * Sofia-SIP stores url_path without the leading '/', so this method returns:
	 * - "/" when the URL has no path;
	 * - "/path" otherwise.
	 */
	std::string getAbsolutePath() const;

	static std::optional<std::string> hasParsingError(const sofiasip::Url& url) noexcept;

private:
	static void checkUrl(const sofiasip::Url& url);
	static std::string normalizePath(std::string_view path);
};

} // namespace flexisip
