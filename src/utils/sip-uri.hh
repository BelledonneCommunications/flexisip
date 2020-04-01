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

#include "event.hh"

namespace sofiasip {

	class InvalidUrlError : public std::invalid_argument {
	public:
		template <typename T, typename U>
		InvalidUrlError(T &&url, U &&reason):
			invalid_argument(url), _url(std::forward<T>(url)), _reason(std::forward<U>(reason)) {}

		const std::string &getUrl() const {return _url;}
		const std::string &getReason() const {return _reason;}

	private:
		std::string _url;
		std::string _reason;
	};

	class UrlModificationError : public std::logic_error {
	public:
		using logic_error::logic_error;
	};

	/**
	 * @brief Class for SIP URI handling, implemented with SofiaSip's url_t.
	 */
	class Url {
	public:
		Url() = default;
		/**
		 * @brief Create a SIP URI object from a string.
		 * @exception std::invalid_argument The string doesn't match with URI grammar.
		 */
		explicit Url(const std::string &str);
		explicit Url(const url_t *src);
		Url(const Url &src) noexcept;
		Url(Url &&src) noexcept;
		virtual ~Url() = default;

		Url &operator=(const Url &src) noexcept;
		Url &operator=(Url &&src) noexcept;

		bool empty() const noexcept {return _url == nullptr;}

		/**
		 * @brief Return a pointer on the underlying sip_t structure.
		 */
		const url_t *get() const noexcept {return _url;}
		/**
		 * @brief Get the URI as string.
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

		Url replaceUser(const std::string &newUser) const;

		bool hasParam(const std::string &name) const {return hasParam(name.c_str());}
		bool hasParam(const char *name) const {return url_has_param(_url, name);}

	protected:
		flexisip::SofiaAutoHome _home;
		const url_t *_url = nullptr;
		mutable std::string _urlAsStr;
	};
}

inline std::ostream &operator<<(std::ostream &os, const sofiasip::Url &url) {return os << url.str();}

namespace flexisip {

	/**
	 * @brief Class for SIP URI handling, implemented with SofiaSip's url_t.
	 */
	class SipUri : public sofiasip::Url {
	public:
		SipUri() = default;
		/**
		 * @brief Create a SIP URI object from a string.
		 * @exception std::invalid_argument The string doesn't match with URI grammar.
		 */
		explicit SipUri(const std::string &str);
		explicit SipUri(const url_t *src);
		explicit SipUri(const sofiasip::Url &src);
		explicit SipUri(sofiasip::Url &&src);
		SipUri(const SipUri &src) noexcept = default;
		SipUri(SipUri &&src) noexcept = default;
		~SipUri() override = default;

		SipUri &operator=(const SipUri &src) noexcept = default;
		SipUri &operator=(SipUri &&src) noexcept = default;

		SipUri replaceUser(const std::string &newUser) const;

	private:
		static void checkUrl(const sofiasip::Url &url);
	};

}
