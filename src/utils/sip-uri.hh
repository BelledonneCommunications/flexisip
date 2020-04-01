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
#include <string>

// Forward declaration of url_t in order SipUri class
// completely hides SofiaSip API.
#ifndef URL_H_TYPES
struct url_t;
#endif

namespace sofiasip {
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
		Url(const std::string &str);
		Url(const url_t *src);
		Url(const Url &src) noexcept;
		Url(Url &&src) noexcept;
		virtual ~Url();

		Url &operator=(const Url &src) noexcept;
		Url &operator=(Url &&src) noexcept;

		bool empty() const noexcept {return _url == nullptr;}

		/**
		 * @brief Return a pointer on the underlying sip_t structure.
		 */
		const url_t *get() const noexcept {return _url.get();}
		/**
		 * @brief Get the URI as string.
		 */
		const std::string &str() const noexcept;

		std::string getScheme() const noexcept;
		std::string getUser() const noexcept;
		std::string getPassword() const noexcept;
		std::string getHost() const noexcept;
		std::string getPort() const noexcept;
		std::string getPath() const noexcept;
		std::string getParams() const noexcept;
		std::string getHeaders() const noexcept;
		std::string getFragment() const noexcept;

	protected:
		using suDeleterT = std::function<void(void *)>;

		static const suDeleterT suObjectDeleter;
		std::unique_ptr<url_t, suDeleterT> _url = {nullptr, suObjectDeleter};
		mutable std::string _urlAsStr;
	};
}

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
		SipUri(const std::string &str);
		SipUri(const url_t *src);
		SipUri(const sofiasip::Url &src);
		SipUri(sofiasip::Url &&src);
		SipUri(const SipUri &src) noexcept = default;
		SipUri(SipUri &&src) noexcept = default;
		~SipUri() override = default;

		SipUri &operator=(const SipUri &src) noexcept = default;
		SipUri &operator=(SipUri &&src) noexcept = default;

	private:
		static void checkUrl(const sofiasip::Url &url);
	};

}
