/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

#include <sofia-sip/nth.h>

#include "flexisip/sofia-wrapper/su-root.hh"

namespace flexisip::tester::http_mock {

/**
 * A simple HTTP1.1 server on localhost
 * Support GET request
 */
class Http1Srv {
public:
	explicit Http1Srv(const std::shared_ptr<sofiasip::SuRoot>& root);

	const char* getFirstPort();

	void addPage(std::string_view subPath, std::string_view body);

	std::string_view getResponse(const std::string& page) {
		const auto response = mResponses.find(page);
		if (response == mResponses.cend()) return {};
		return response->second;
	}

private:
	std::shared_ptr<sofiasip::SuRoot> mRoot;

	struct NthSiteDeleter {
		void operator()(nth_site_t* site) {
			nth_site_destroy(site);
		}
	};

	std::unique_ptr<nth_site_t, NthSiteDeleter> mSite;
	std::unordered_map<std::string, std::string> mResponses;
};
} // namespace flexisip::tester::http_mock
