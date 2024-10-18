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

#include "utils/core-assert.hh"
#include "utils/http-mock/http1-mock.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/http/http1-client.hh"

using namespace flexisip;
using namespace flexisip::tester;

namespace {
void getLowVolumeData() {
	auto root = std::make_shared<sofiasip::SuRoot>();
	http_mock::Http1Srv httpSvr(root);
	std::string body{"body"};
	auto url = httpSvr.addPage("/TEST", body);
	BC_HARD_ASSERT(!url.empty());

	Http1Client httpClient(root);
	bool receivedResponse = false;
	httpClient.requestGET(url, [&receivedResponse, &body](std::string_view data) {
		receivedResponse = true;
		BC_ASSERT_CPP_EQUAL(data, body);
	});
	CoreAssert{root}
	    .iterateUpTo(10,
	                 [&receivedResponse] {
		                 FAIL_IF(!receivedResponse);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
}

void getHighVolumeData() {
	auto root = std::make_shared<sofiasip::SuRoot>();
	http_mock::Http1Srv httpSvr(root);
	std::string body{};
	auto experimentalValueToGenerateFragmentedMessage = 99000;
	body.resize(experimentalValueToGenerateFragmentedMessage, 'x');
	auto url = httpSvr.addPage("TEST", body);
	BC_HARD_ASSERT(!url.empty());

	Http1Client httpClient(root);
	bool receivedResponse = false;
	httpClient.requestGET(url, [&receivedResponse, &body](std::string_view data) {
		receivedResponse = true;
		BC_ASSERT_CPP_EQUAL(data.size(), body.size());
		BC_ASSERT_TRUE(data == body);
	});
	CoreAssert{root}
	    .iterateUpTo(10,
	                 [&receivedResponse] {
		                 FAIL_IF(!receivedResponse);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
}

// ensure the callback is called with empty data when status is not 200
void callbackOnFailure() {
	auto root = std::make_shared<sofiasip::SuRoot>();
	http_mock::Http1Srv httpSvr(root);

	Http1Client httpClient(root);
	bool receivedResponse = false;
	httpClient.requestGET(httpSvr.getUrl() + "/NotFound", [&receivedResponse](std::string_view data) {
		receivedResponse = true;
		BC_ASSERT_TRUE(data.empty());
	});
	CoreAssert{root}
	    .iterateUpTo(10,
	                 [&receivedResponse] {
		                 FAIL_IF(!receivedResponse);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
}

const TestSuite kSuite{
    "Http1Client",
    {
        CLASSY_TEST(getLowVolumeData),
        CLASSY_TEST(getHighVolumeData),
        CLASSY_TEST(callbackOnFailure),
    },
};
} // namespace