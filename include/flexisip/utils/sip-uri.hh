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
#include <string>
#include <string_view>
#include <unordered_map>

#include "sofia-sip/tport.h"
#include "sofia-sip/url.h"

#include "flexisip/sofia-wrapper/home.hh"
#include "flexisip/sofia-wrapper/url.hh"

namespace flexisip {

/**
 * A specialisation of sofiasip::Url which ensures that the URL is a SIP or SIPS URI.
 */
class SipUri : public sofiasip::Url {
public:
	class Params {
	public:
		explicit Params(const char* parameters);

		bool operator==(const Params& other) const;
		bool operator!=(const Params& other) const {
			return !(*this == other);
		}

		std::string getParameter(const std::string& name) const;

		bool removeParameter(const std::string& name);

		/**
		 * @return parameters list as a string (example: ";param=value;other-param=other-value")
		 */
		std::string toString() const;

		bool empty() const;

	private:
		std::unordered_map<std::string, std::string> mParams{};
	};

	class Headers {
	public:
		explicit Headers(const char* c);

		bool operator==(const Headers& other) const;
		bool operator!=(const Headers& other) const {
			return !(*this == other);
		}

	private:
		static constexpr std::string_view mLogPrefix{"SipUri::Headers"};

		std::unordered_map<std::string, std::string> mHeaders{};
	};

	enum class Scheme : std::underlying_type_t<url_type_e> {
		invalid = url_invalid,
		any = url_any, // The star '*' scheme.
		sip = url_sip,
		sips = url_sips,
		none = _url_none,
	};

	enum class SipScheme : std::underlying_type_t<Scheme> {
		sip = static_cast<url_type_e>(Scheme::sip),
		sips = static_cast<url_type_e>(Scheme::sips),
	};

	/**
	 * @brief Build a SipUri from information contained in a sofia-sip tport name instance.
	 *
	 * @param name information to create the URI.
	 */
	static SipUri fromName(const tp_name_t* name);

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
	 * @note if 'transport=tls' is present, the URI will be considered as a SIPS URI.
	 * @note if 'transport=udp' is present, the URI will be considered as a SIP URI (and parameter is removed).
	 *
	 * @param userInfo user information (without '@')
	 * @param hostport domain or IP address (and optionally port)
	 * @param parameters URI parameters (example: "param=value;other-parm=other-value")
	 */
	SipUri(std::string_view userInfo, std::string_view hostport, Params params = Params{""});

	explicit SipUri(sofiasip::Url&& src);
	SipUri(const SipUri& src) noexcept = default;
	SipUri(SipUri&& src) noexcept = default;
	~SipUri() override = default;

	SipUri& operator=(const SipUri& src) noexcept = default;
	SipUri& operator=(SipUri&& src) noexcept = default;

	Scheme getSchemeType() const noexcept;

	/**
	 * @throw sofiasip::UrlModificationError if the URL is empty
	 */
	[[nodiscard]] SipUri replaceScheme(Scheme newScheme) const;
	/**
	 * @throw sofiasip::UrlModificationError if the URL is empty
	 */
	[[nodiscard]] SipUri replaceUser(std::string_view newUser) const;

	/**
	 * @throw sofiasip::UrlModificationError if the URL is empty
	 */
	[[nodiscard]] SipUri replaceHost(std::string_view newHost) const;

	/**
	 * @throw sofiasip::UrlModificationError if the URL is empty
	 */
	[[nodiscard]] SipUri replacePort(std::string_view newPort) const;
	/**
	 * @throw sofiasip::UrlModificationError if the URL is empty
	 */
	[[nodiscard]] SipUri setParameter(const std::string& name, const std::string& value) const;

	/**
	 * True if this URI is the same as the other according to RFC 3261.
	 * https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.4
	 */
	bool rfc3261Compare(const url_t* other) const;
	bool rfc3261Compare(const SipUri& other) const {
		return rfc3261Compare(other._url);
	}

	// Check validity of a sip uri raw url and return an error message when it is invalid.
	static std::optional<std::string> hasParsingError(const url_t* url) noexcept {
		return hasParsingError(sofiasip::Url(url));
	}
	static std::optional<std::string> hasParsingError(const sofiasip::Url& url) noexcept;

private:
	/**
	 * Create and initialize from a SIP scheme.
	 */
	explicit SipUri(SipScheme type);

	static void checkUrl(const sofiasip::Url& url);
};

/*
 * Nice << operator to serialize sofia-sip 's url_t */
std::ostream& operator<<(std::ostream& strm, const url_t& obj);

} // namespace flexisip