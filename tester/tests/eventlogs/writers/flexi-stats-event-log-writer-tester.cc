/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "eventlogs/writers/flexi-stats-event-log-writer.hh"

#include <atomic>

#include "bctoolbox/tester.h"

#include "utils/client-core.hh"
#include "utils/eventlogs/event-logs.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace {
using namespace flexisip;
using namespace flexisip::tester;
using namespace flexisip::tester::eventlogs;
using namespace std;

void callStartedAndEnded() {
	using namespace nlohmann;

	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};
	int port = httpMock.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);

	// See makeAndStartProxy for event-log configuration
	const auto proxy = makeAndStartProxy({{"event-logs/enabled", "true"},
	                                      {"event-logs/logger", "flexiapi"},
	                                      {"event-logs/flexiapi-host", "localhost"},
	                                      {"event-logs/flexiapi-port", to_string(port)},
	                                      {"event-logs/flexiapi-prefix", "api/stats"},
	                                      {"event-logs/flexiapi-token", "aRandomApiToken"}});
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	auto tony = ClientBuilder("sip:" + expectedFrom).registerTo(proxy);
	auto mike = ClientBuilder("sip:" + expectedTo).registerTo(proxy);
	const auto expectedDeviceId = "\"<urn:uuid:" + uuidOf(*mike.getCore()) + ">\"";

	tony.call(mike);

	BcAssert asserter{[&proxy] { proxy->getRoot()->step(10ms); }};
	BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(10, [&requestsReceivedCount] { return requestsReceivedCount == 3; }));

	const auto startedEvent = httpMock.popRequestReceived();
	BC_HARD_ASSERT(startedEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(startedEvent->method, "POST");
	BC_ASSERT_CPP_EQUAL(startedEvent->path, "/api/stats/calls");
	json actualJson;
	try {
		actualJson = json::parse(startedEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto logId = actualJson["id"].get<string>();
	actualJson.erase("id");
	actualJson.erase("initiated_at");
	actualJson.erase("ended_at");
	json expectedJson = {
	    {"from", expectedFrom},
	    {"to", expectedTo},
	    {"conference_id", nullptr},
	    {"devices",
	     {
	         {expectedDeviceId, nullptr},
	     }},
	};
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	const auto ringingEvent = httpMock.popRequestReceived();
	BC_HARD_ASSERT(ringingEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(ringingEvent->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(ringingEvent->path, "/api/stats/calls/" + logId + "/devices/" + expectedDeviceId);
	try {
		actualJson = json::parse(ringingEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	BC_ASSERT_TRUE(actualJson.contains("rang_at"));
	const auto acceptedEvent = httpMock.popRequestReceived();
	BC_HARD_ASSERT(acceptedEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(acceptedEvent->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(acceptedEvent->path, "/api/stats/calls/" + logId + "/devices/" + expectedDeviceId);
	try {
		actualJson = json::parse(acceptedEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	actualJson["invite_terminated"].erase("at");
	expectedJson = R"(
	{
		"invite_terminated": {
			"state": "accepted"
		}
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	requestsReceivedCount = 0;

	tony.endCurrentCall(mike);

	BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(10, [&requestsReceivedCount] { return requestsReceivedCount == 1; }));

	const auto endedEvent = httpMock.popRequestReceived();
	BC_ASSERT_CPP_EQUAL(endedEvent->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(endedEvent->path, "/api/stats/calls/" + logId);
	try {
		actualJson = json::parse(endedEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	BC_ASSERT_TRUE(actualJson.contains("ended_at"));
}

TestSuite _("FlexiStatsEventLogWriter",
            {
                CLASSY_TEST(callStartedAndEnded),
            });
} // namespace
