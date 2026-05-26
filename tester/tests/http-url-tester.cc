/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/utils/http-url.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {

void parsingUrl() {
	// Valid url
	sofiasip::Url url{"http://example.org/api/push"};
	auto parsingError = HttpUrl::hasParsingError(url);
	BC_ASSERT_FALSE(parsingError.has_value());

	// Scheme
	url = sofiasip::Url("://example.org/api/push");
	std::string errorMessage = HttpUrl::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "no scheme found");

	url = sofiasip::Url("http");
	errorMessage = HttpUrl::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "no scheme found");

	url = sofiasip::Url("soap://example.org/api/push");
	errorMessage = HttpUrl::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "invalid scheme (soap)");

	// Host
	url = sofiasip::Url{"http:///api/push"};
	errorMessage = HttpUrl::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "no host found");
}

void changeUrlPath() {
	HttpUrl baseUrl{"http://example.org"};

	BC_ASSERT_CPP_EQUAL(baseUrl.getPath(), "");
	BC_ASSERT_CPP_EQUAL(baseUrl.getAbsolutePath(), "/");

	// Replace path
	HttpUrl url = baseUrl.replacePath("api/push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.replacePath("/api/push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.replacePath("//api/push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.replacePath("/api/push/");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push/");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push/");

	url = baseUrl.replacePath("/");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/");

	url = baseUrl.replacePath("///////");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/");

	// Append path
	url = baseUrl.appendPath("api/push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.appendPath("api").appendPath("push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.appendPath("/api").appendPath("/push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.appendPath("api/").appendPath("push");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push");

	url = baseUrl.appendPath("/api/").appendPath("/push/");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "api/push/");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/api/push/");

	url = baseUrl.appendPath("this")
	          .appendPath("/is")
	          .appendPath("a/")
	          .appendPath("////totally///")
	          .appendPath("normal")
	          .appendPath("/p/a/t/////h");
	BC_ASSERT_CPP_EQUAL(url.getPath(), "this/is/a/totally/normal/p/a/t/h");
	BC_ASSERT_CPP_EQUAL(url.getAbsolutePath(), "/this/is/a/totally/normal/p/a/t/h");
}

namespace {

TestSuite _{
    "HttpUrl",
    {CLASSY_TEST(parsingUrl), CLASSY_TEST(changeUrlPath)},
};
}
} // namespace flexisip::tester