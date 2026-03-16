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

#include "accounts-store/fam-data.hh"
#include "flexiapi/config.hh"

#include <fstream>

#include "utils/core-assert.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
namespace flexisip::tester {
namespace {
std::optional<TmpDir> kSuiteDir;

const auto accountInitialApiUri = "/api/resolve/initial-callee@sip.example.org";
const auto accountInitial = R"({
            "type": "account",
            "payload": {
				"id": 0,
		        "sip_uri": "sip:initial-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "contact_sip_uri": "sip:busy-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        },
					{
				        "type": "always",
				        "sip_uri": "sip:fail_if_returned@sip.example.org",
				        "forward_to": "sip_uri",
						"enabled": false
			        },
			        {
				        "type": "always",
				        "contact_sip_uri": "sip:intermediate-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        }
		        ]
            }
        })";
const std::vector<flexiapi::CallForwarding> expectedInitialDiversions{
    {.type = flexiapi::CallForwarding::Type::Busy,
     .forward_to = flexiapi::CallForwarding::ForwardType::Contact,
     .sip_uri = SipUri("sip:busy-callee@sip.example.org"),
     .enabled = true},
    {.type = flexiapi::CallForwarding::Type::Always,
     .forward_to = flexiapi::CallForwarding::ForwardType::SipUri,
     .sip_uri = SipUri("sip:fail_if_returned@sip.example.org"),
     .enabled = false},
    {.type = flexiapi::CallForwarding::Type::Always,
     .forward_to = flexiapi::CallForwarding::ForwardType::Contact,
     .sip_uri = SipUri("sip:intermediate-callee@sip.example.org"),
     .enabled = true},
};
const auto accountIntermediateApiUri = "/api/accounts/intermediate-callee@sip.example.org/search";
const auto accountIntermediate = R"({
			"id": 0,
	        "sip_uri": "sip:intermediate-callee@sip.example.org",
	        "call_forwardings": [
		        {
			        "type": "always",
			        "sip_uri": "sip:final-callee@sip.example.org",
			        "forward_to": "sip_uri",
					"enabled": true
		        }
	        ]
        })";
const auto accountFinalApiUri = "/api/resolve/final-callee@sip.example.org";
const auto accountFinal = R"({
			"type": "account",
            "payload": {
				"id": 0,
				"sip_uri": "sip:final-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "contact_sip_uri": "sip:initial-callee@sip.example.org",
				        "forward_to": "contact",
						"enabled": true
			        }
		        ]
			}
        })";

int numberOfCalls = 0;
const std::map<std::string, http_mock::HttpMockHandler> basicHandlers = {
    {accountInitialApiUri,
     [](http_mock::HttpMock&,
        const nghttp2::asio_http2::server::request&,
        const nghttp2::asio_http2::server::response& res) {
	     numberOfCalls++;
	     res.write_head(200);
	     res.end(accountInitial);
     }},
    {accountIntermediateApiUri,
     [](http_mock::HttpMock&,
        const nghttp2::asio_http2::server::request&,
        const nghttp2::asio_http2::server::response& res) {
	     numberOfCalls++;
	     res.write_head(200);
	     res.end(accountIntermediate);
     }},
    {accountFinalApiUri, [](http_mock::HttpMock&,
                            const nghttp2::asio_http2::server::request&,
                            const nghttp2::asio_http2::server::response& res) {
	     numberOfCalls++;
	     res.write_head(200);
	     res.end(accountFinal);
     }}};

std::pair<unique_ptr<http_mock::HttpMock>, int>
setupFamMock(const std::map<std::string, http_mock::HttpMockHandler>& customHandlers = {}) {
	auto famMock = make_unique<http_mock::HttpMock>(customHandlers.empty() ? basicHandlers : customHandlers);
	return {std::move(famMock), famMock->serveAsync()};
}

struct TestCommons {
	explicit TestCommons(const int httpPort,
	                     const chrono::milliseconds cacheTimeout = 30s,
	                     const chrono::milliseconds unknownTimeout = 10min)
	    : proxy{{
	          {"global::flexiapi/url", "https://127.0.0.1:"s + to_string(httpPort)},
	      }},
	      data{flexiapi::createRestClient(*proxy.getConfigManager(),
	                                      flexiapi::createClient(proxy.getConfigManager(), *proxy.getRoot())),
	           proxy.getRoot(), cacheTimeout, unknownTimeout} {}

	Server proxy;
	FAMData data;
	CoreAssert<> asserter{proxy.getRoot()};
};

void assertDiversionsEqual(const std::vector<flexiapi::CallForwarding>& diversions,
                           const std::vector<flexiapi::CallForwarding>& expectedDiversions) {
	BC_ASSERT_CPP_EQUAL(diversions.size(), expectedDiversions.size());
	for (size_t i = 0; i < diversions.size(); ++i) {
		BC_ASSERT_CPP_EQUAL(diversions[i].type, expectedDiversions[i].type);
		BC_ASSERT_CPP_EQUAL(diversions[i].forward_to, expectedDiversions[i].forward_to);
		BC_ASSERT_CPP_EQUAL(diversions[i].enabled, expectedDiversions[i].enabled);
		BC_ASSERT_TRUE(diversions[i].sip_uri.rfc3261Compare(expectedDiversions[i].sip_uri));
	}
}

void findCallDiversions_Initial() {
	const auto [famMock, httpPort] = setupFamMock();
	auto commons = TestCommons{httpPort};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });

	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
}

void findCallDiversions_Intermediate() {
	const auto [famMock, httpPort] = setupFamMock();
	auto commons = TestCommons{httpPort};

	std::vector<flexiapi::CallForwarding> expectedDiversions{
	    {.type = flexiapi::CallForwarding::Type::Always,
	     .forward_to = flexiapi::CallForwarding::ForwardType::SipUri,
	     .sip_uri = SipUri("sip:final-callee@sip.example.org"),
	     .enabled = true},
	};

	bool callbackCalled{false};
	commons.data.findCallDiversions(
	    SipUri("sip:intermediate-callee@sip.example.org"), flexiapi::CallForwarding::ForwardType::Contact,
	    [&callbackCalled, &expectedDiversions](const std::vector<flexiapi::CallForwarding>& diversions) {
		    assertDiversionsEqual(diversions, expectedDiversions);
		    callbackCalled = true;
	    });

	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
}

void findCallDiversions_IntermediateWrongForwardType() {
	const auto [famMock, httpPort] = setupFamMock();
	auto commons = TestCommons{httpPort};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:intermediate-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });

	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
}

void findCallDiversions_Final() {
	const auto [famMock, httpPort] = setupFamMock();
	auto commons = TestCommons{httpPort};

	std::vector<flexiapi::CallForwarding> expectedDiversions{
	    {.type = flexiapi::CallForwarding::Type::Busy,
	     .forward_to = flexiapi::CallForwarding::ForwardType::Contact,
	     .sip_uri = SipUri("sip:initial-callee@sip.example.org"),
	     .enabled = true},
	};

	bool callbackCalled{false};
	commons.data.findCallDiversions(
	    SipUri("sip:final-callee@sip.example.org"), flexiapi::CallForwarding::ForwardType::SipUri,
	    [&callbackCalled, &expectedDiversions](const std::vector<flexiapi::CallForwarding>& diversions) {
		    assertDiversionsEqual(diversions, expectedDiversions);
		    callbackCalled = true;
	    });

	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
}

void findCallDiversions_FamKo() {
	const std::map<std::string, http_mock::HttpMockHandler> customHandlers = {
	    {accountInitialApiUri, [](http_mock::HttpMock&, const nghttp2::asio_http2::server::request&,
	                              const nghttp2::asio_http2::server::response& res) {
		     res.write_head(503);
		     res.end();
	     }}};
	const auto [famMock, httpPort] = setupFamMock(customHandlers);
	auto commons = TestCommons{httpPort};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });

	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
}

void findCallDiversions_badJsonTemplate(const string& badJson = "") {
	std::map<std::string, http_mock::HttpMockHandler> customHandlers = basicHandlers;
	customHandlers[accountInitialApiUri] = [badJson](http_mock::HttpMock&, const nghttp2::asio_http2::server::request&,
	                                                 const nghttp2::asio_http2::server::response& res) {
		res.write_head(200);
		res.end(badJson);
	};
	const auto [famMock, httpPort] = setupFamMock(customHandlers);
	auto commons = TestCommons{httpPort};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });

	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
}

void findCallDiversions_noJson() {
	findCallDiversions_badJsonTemplate("I AM NOT JSON");
}

void findCallDiversions_badJsonInPayload() {
	findCallDiversions_badJsonTemplate(R"({
            "type": "account",
            "payload": {
				"id": 0,
		        "BAD_ENTRY": "sip:initial-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "target": "sip:busy-callee@sip.example.org",
				        "target_type": "account"
			        },
			        {
				        "type": "always",
				        "target": "sip:intermediate-callee@sip.example.org",
				        "target_type": "account"
			        }
		        ]
            }
        })");
}

void findCallDiversions_badJsonType() {
	findCallDiversions_badJsonTemplate(R"({
            "type": "BAD_TYPE",
            "payload": {
				"id": 0,
		        "sip_uri": "sip:initial-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "target": "sip:busy-callee@sip.example.org",
				        "target_type": "account"
			        },
			        {
				        "type": "always",
				        "target": "sip:intermediate-callee@sip.example.org",
				        "target_type": "account"
			        }
		        ]
            }
        })");
}

void findCallDiversions_badJsonSipUri() {
	findCallDiversions_badJsonTemplate(R"({
            "type": "account",
            "payload": {
				"id": 0,
		        "sip_uri": "sip:initial-callee@sip.example.org",
		        "call_forwardings": [
			        {
				        "type": "busy",
				        "target": "BAD_SIP_URI",
				        "target_type": "account"
			        },
			        {
				        "type": "always",
				        "target": "sip:intermediate-callee@sip.example.org",
				        "target_type": "account"
			        }
		        ]
            }
        })");
}

void cacheHitTest() {
	const auto [famMock, httpPort] = setupFamMock();
	auto commons = TestCommons{httpPort};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);

	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);

	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);
}

void cacheResetTest() {
	const auto [famMock, httpPort] = setupFamMock();
	auto commons = TestCommons{httpPort, 1ms};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);

	commons.asserter.forceIterateThenAssert(10, 5ms, [] { return true; }).assert_passed();
	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 2);

	commons.asserter.forceIterateThenAssert(10, 5ms, [] { return true; }).assert_passed();
	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                assertDiversionsEqual(diversions, expectedInitialDiversions);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 3);
}

void unknownHitTest() {
	const std::map<std::string, http_mock::HttpMockHandler> customHandlers = {
		{accountInitialApiUri, [](http_mock::HttpMock&, const nghttp2::asio_http2::server::request&,
								  const nghttp2::asio_http2::server::response& res) {
			numberOfCalls++;
			res.write_head(404);
			res.end();
		}}};
	const auto [famMock, httpPort] = setupFamMock(customHandlers);
	auto commons = TestCommons{httpPort};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);

	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);

	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);
}

void unknownResetTest() {
	const std::map<std::string, http_mock::HttpMockHandler> customHandlers = {
		{accountInitialApiUri, [](http_mock::HttpMock&, const nghttp2::asio_http2::server::request&,
								  const nghttp2::asio_http2::server::response& res) {
			numberOfCalls++;
			res.write_head(404);
		 res.end();
		}}};
	const auto [famMock, httpPort] = setupFamMock(customHandlers);
	auto commons = TestCommons{httpPort, 30s, 1ms};

	bool callbackCalled{false};
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 1);

	commons.asserter.forceIterateThenAssert(10, 5ms, [] { return true; }).assert_passed();
	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 2);

	commons.asserter.forceIterateThenAssert(10, 5ms, [] { return true; }).assert_passed();
	callbackCalled = false;
	commons.data.findCallDiversions(SipUri("sip:initial-callee@sip.example.org"),
	                                flexiapi::CallForwarding::ForwardType::SipUri,
	                                [&callbackCalled](const std::vector<flexiapi::CallForwarding>& diversions) {
		                                BC_ASSERT_CPP_EQUAL(diversions.size(), 0);
		                                callbackCalled = true;
	                                });
	commons.asserter.wait([&callbackCalled] { return callbackCalled; }).hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(numberOfCalls, 3);
}

TestSuite kSuite{
    "FamData",
    {
        CLASSY_TEST(findCallDiversions_Initial),
        CLASSY_TEST(findCallDiversions_Intermediate),
        CLASSY_TEST(findCallDiversions_IntermediateWrongForwardType),
        CLASSY_TEST(findCallDiversions_Final),
        CLASSY_TEST(findCallDiversions_FamKo),
        CLASSY_TEST(findCallDiversions_noJson),
        CLASSY_TEST(findCallDiversions_badJsonInPayload),
        CLASSY_TEST(findCallDiversions_badJsonType),
        CLASSY_TEST(findCallDiversions_badJsonSipUri),
        CLASSY_TEST(cacheHitTest),
        CLASSY_TEST(cacheResetTest),
        CLASSY_TEST(unknownHitTest),
        CLASSY_TEST(unknownResetTest),
    },
    Hooks()
        .beforeSuite([] {
	        kSuiteDir.emplace(kSuite.getName());
	        return 0;
        })
        .afterSuite([] {
	        kSuiteDir.reset();
	        return 0;
        })
        .beforeEach([] { numberOfCalls = 0; }),
};
} // namespace
} // namespace flexisip::tester
