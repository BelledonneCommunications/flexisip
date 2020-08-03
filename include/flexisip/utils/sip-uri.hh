/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2019  Belledonne Communications SARL.

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

#include <sofia-sip/url.h>

#include <flexisip/sofia-wrapper/home.hh>

namespace sofiasip {

	/**
	 * Exception thrown while trying to create a new URL from
	 * an invalid string or url_t.
	 */
	class InvalidUrlError : public std::invalid_argument {
	public:
		template <typename T, typename U>
		InvalidUrlError(T &&url, U &&reason) noexcept:
			invalid_argument(url), _url(std::forward<T>(url)), _reason(std::forward<U>(reason)) {}

		/**
		 * Get the string that couldn't be parsed.
		 */
		const std::string &getUrl() const noexcept {return _url;}
		/**
		 * Get the reason of the parsing failure.
		 */
		const std::string &getReason() const noexcept {return _reason;}

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
		explicit Url(const std::string &str);
		/**
		 * Create an URL from a SofiaSip's url_t structure.
		 * The url_t structure isn't modified and all the allocated
		 * string are duplicated.
		 */
		explicit Url(const url_t *src) noexcept;
		Url(const Url &src) noexcept;
		/**
		 * Move constructor.
		 * @note src become an empty URL after the process.
		 */
		Url(Url &&src) noexcept;
		virtual ~Url() = default;

		Url &operator=(const Url &src) noexcept;
		/**
		 * Move assign operator.
		 * @note src become an empty URL after the process.
		 */
		Url &operator=(Url &&src) noexcept;

		/**
		 * Test whether the URL is empty.
		 */
		bool empty() const noexcept {return _url == nullptr;}

		/**
		 * Return a pointer on the underlying sip_t structure.
		 */
		const url_t *get() const noexcept {return _url;}
		/**
		 * Format the URL as string.
		 * @note The result of formating is cached.
		 */
		const std::string &str() const noexcept;

		#define getUrlAttr(attr) _url && _url->attr ? _url->attr : ""
		std::string getScheme() const noexcept {return getUrlAttr(url_scheme);}
		std::string getUser() const noexcept {return getUrlAttr(url_user);}
		std::string getPassword() const noexcept {return getUrlAttr(url_password);}
		std::string getHost() const noexcept {return getUrlAttr(url_host);}
		std::string getPort() const noexcept {return getUrlAttr(url_port);}
		std::string getPath() const noexcept {return getUrlAttr(url_path);}
		std::string getParams() const noexcept {return getUrlAttr(url_params);}
		std::string getHeaders() const noexcept {return getUrlAttr(url_headers);}
		std::string getFragment() const noexcept {return getUrlAttr(url_fragment);}
		#undef getUrlAttr

		/**
		 * Create a new URL by replacing the user past by another string.
		 * @throw UrlModificationError when the actual URL is empty or
		 * the new URL would be invalid.
		 */
		Url replaceUser(const std::string &newUser) const;

		/**
		 * Test whether the URL has a given param by its name.
		 */
		bool hasParam(const std::string &name) const noexcept {return hasParam(name.c_str());}
		bool hasParam(const char *name) const noexcept {return url_has_param(_url, name);}

	protected:
		Home _home;
		const url_t *_url = nullptr;
		mutable std::string _urlAsStr;
	};
}

inline std::ostream &operator<<(std::ostream &os, const sofiasip::Url &url) {return os << url.str();}

namespace flexisip {

	/**
	 * A specialisation of sofiasip::Url which ensures that the URL is a
	 * SIP or SIPS URI.
	 */
	class SipUri : public sofiasip::Url {
	public:
		SipUri() = default;
		/**
		 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
		 */
		explicit SipUri(const std::string &str);
		/**
		 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
		 */
		explicit SipUri(const url_t *src);
		/**
		 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
		 */
		explicit SipUri(const sofiasip::Url &src);
		/**
		 * @throw sofiasip::InvalidUrlError if str isn't a SIP or SIPS URI.
		 */
		explicit SipUri(sofiasip::Url &&src);
		SipUri(const SipUri &src) noexcept = default;
		SipUri(SipUri &&src) noexcept = default;
		~SipUri() override = default;

		SipUri &operator=(const SipUri &src) noexcept = default;
		SipUri &operator=(SipUri &&src) noexcept = default;

		/**
		 * @throw sofiasip::UrlModificationError if the URL is empty or
		 * the result would be an invalid SIP URI.
		 */
		SipUri replaceUser(const std::string &newUser) const;

	private:
		static void checkUrl(const sofiasip::Url &url);
	};

}
