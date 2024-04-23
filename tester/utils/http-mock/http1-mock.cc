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

#define NTH_SITE_MAGIC_T void

#include "http1-mock.hh"

#include <sofia-sip/http_header.h>

#include "flexisip/sofia-wrapper/home.hh"

namespace flexisip::tester::http_mock {

Http1Srv::Http1Srv(const std::shared_ptr<sofiasip::SuRoot>& root) : mRoot{root} {
	auto cb = [](nth_site_magic_t*, nth_site_t*, nth_request_t* req, http_t const*, char const*) {
		nth_request_treply(req, HTTP_405_NOT_ALLOWED, HTTPTAG_ALLOW_STR("GET"), TAG_END());
		return 405;
	};
	mSite.reset(nth_site_create(nullptr, cb, this, reinterpret_cast<const url_string_t*>("http://127.0.0.1:0"),
	                            NTHTAG_ROOT(mRoot->getCPtr()), TAG_END()));
}

const char* Http1Srv::getFirstPort() {
	return nth_site_get_first_port(mSite.get());
}

void Http1Srv::addPage(std::string_view subPath, std::string_view body) {
	auto cb = [](nth_site_magic_t* ctx, nth_site_t* s, nth_request_t* req, http_t const*, char const*) {
		auto thiz = static_cast<flexisip::tester::http_mock::Http1Srv*>(ctx);
		auto rep = thiz->getResponse(nth_site_url(s)->url_path);
		if (rep.empty()) return 500;
		sofiasip::Home home{};
		auto payload = http_payload_create(home.home(), rep.data(), static_cast<isize_t>(rep.size()));
		nth_request_treply(req, HTTP_200_OK, HTTPTAG_ALLOW_STR("GET"), HTTPTAG_PAYLOAD(payload), TAG_END());
		return 200;
	};
	auto page =
	    nth_site_create(mSite.get(), cb, this, reinterpret_cast<const url_string_t*>(subPath.data()), TAG_END());
	if (page) mResponses[nth_site_url(page)->url_path] = body;
}

} // namespace flexisip::tester::http_mock
