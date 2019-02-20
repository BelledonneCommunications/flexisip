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

#include <string>

#include <sofia-sip/url.h>

namespace flexisip {

	/**
	 * @brief Class for SIP URI handling, implemented with SofiaSip's url_t.
	 */
	class SipUri {
	public:
		/**
		 * @brief Create a SIP URI object from a string.
		 * @exception std::invalid_argument The string doesn't match with URI grammar.
		 */
		SipUri(const std::string &str);
		~SipUri();

		/**
		 * @brief Return a pointer on the underlying sip_t structure.
		 */
		const url_t *get() const {return _url;}
		/**
		 * @brief Get the URI as string.
		 */
		const std::string &str() const;

	private:
		su_home_t _home;
		url_t *_url = nullptr;
		mutable std::string _urlAsStr;
	};

}
