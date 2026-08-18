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

#include "eventlogs/writers/flexi-stats-event-log-writer.hh"

#include <atomic>
#include <memory>
#include <regex>
#include <unordered_map>

#include "bctoolbox/tester.h"
#include "linphone++/enums.hh"

#include "flexiapi/schemas/iso-8601-date.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/module-router.hh"
#include "utils/asserts.hh"
#include "utils/bc-utils.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/eventlogs/event-logs.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/server/mysql/mysql-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace nlohmann;

namespace flexisip::tester::eventlogs {
using namespace flexisip::tester::http_mock;

optional<MysqlServer> sDbServer{nullopt};

RestClient getRestClient(sofiasip::SuRoot& root, const string& host, int port, const string& apiKey) {
	const auto http2Client = Http2Client::make(root, host, to_string(port));
	return RestClient{http2Client, HttpHeaders{
	                                   {"accept", "application/json"},
	                                   {"x-api-key"s, apiKey},
	                               }};
}

void startCallAndCheckAuthority(const shared_ptr<flexisip::tester::Server>& proxy,
                                HttpMock& flexiapiServer,
                                std::atomic_int& eventLogRequestsReceivedCount,
                                const string& expectedAuthority) {

	eventLogRequestsReceivedCount = 0;
	const ClientBuilder builder{proxy->getAgent()};
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	auto tony = builder.build(expectedFrom);
	auto mike = builder.build(expectedTo);
	const auto expectedDeviceId = mike.getGruu();

	const auto expectedCallId = tony.call(mike)->getCallLog()->getCallId();
	// expect to received 3 event logs: INVITE, 180 Ringing, 200 OK

	BcAssert asserter{[&proxy] { proxy->getRoot()->step(10ms); }};
	BC_HARD_ASSERT_TRUE(
	    asserter.iterateUpTo(5, [&eventLogRequestsReceivedCount] { return eventLogRequestsReceivedCount == 3; }));

	const auto startedEvent = flexiapiServer.popRequestReceived();
	BC_HARD_ASSERT(startedEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(startedEvent->method, "POST");
	BC_ASSERT_CPP_EQUAL(startedEvent->path, "/api/stats/calls");
	BC_ASSERT_CPP_EQUAL(startedEvent->authority, expectedAuthority);
}

void startLogWriter() {

	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	{
		// No parameters, nor default value for host.
		std::map<std::string, std::string> customConfigs = {
		    {"event-logs/enabled", "true"},
		    {"event-logs/logger", "flexiapi"},
		    {"event-logs/flexiapi-host", ""}, // Set to empty, to not get the default value.
		};
		BC_ASSERT_THROWN(makeAndStartProxy(customConfigs), BadConfigurationEmpty);
	}
	{
		// global::flexiapi/url is empty.
		std::map<std::string, std::string> customConfigs = {
		    {"event-logs/enabled", "true"},
		    {"event-logs/logger", "flexiapi"},
		    {"event-logs/flexiapi-host", ""}, // Set to empty, to not get the default value.
		    {"global::flexiapi/url", ""}};
		BC_ASSERT_THROWN(makeAndStartProxy(customConfigs), BadConfigurationEmpty);
	}
	{
		// global::flexiapi/api-key is empty.
		std::map<std::string, std::string> customConfigs = {
		    {"event-logs/enabled", "true"},
		    {"event-logs/logger", "flexiapi"},
		    {"event-logs/flexiapi-host", ""}, // Set to empty, to not get the default value.
		    {"global::flexiapi/url", "https://flexiapi.com"}};
		BC_ASSERT_THROWN(makeAndStartProxy(customConfigs), BadConfigurationEmpty);
	}
	{
		// global::flexiapi parameters are empty, the (deprecated) default values for event-logs are used.
		std::map<std::string, std::string> customConfigs = {{"event-logs/enabled", "true"},
		                                                    {"event-logs/logger", "flexiapi"}};
		makeAndStartProxy(customConfigs);
	}
	{
		// Set deprecated parameters from event-logs section.
		std::map<std::string, std::string> customConfigs = {{"event-logs/enabled", "true"},
		                                                    {"event-logs/logger", "flexiapi"},
		                                                    {"event-logs/flexiapi-host", "127.0.0.1"},
		                                                    {"event-logs/flexiapi-port", to_string(port)},
		                                                    {"event-logs/flexiapi-prefix", "api/stats"},
		                                                    {"event-logs/flexiapi-api-key", "aRandomApiToken"}};
		makeAndStartProxy(customConfigs);
	}
	{
		// global::flexiapi/url isn't a https url.
		std::map<std::string, std::string> customConfigs = {
		    {"event-logs/enabled", "true"},
		    {"event-logs/logger", "flexiapi"},
		    {"event-logs/flexiapi-host", ""}, // Set to empty, to not get the default value.
		    {"global::flexiapi/url", "flexiapi.com:"s + to_string(port)},
		    {"global::flexiapi/api-key", "aRandomApiToken"}};
		BC_ASSERT_THROWN(makeAndStartProxy(customConfigs), BadConfigurationValue);
	}
}

void startLogWriterMissingUrl() {
	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	// Event-logs parameters are used as global::flexiapi/url is missing .
	std::map<std::string, std::string> customConfigs = {{"event-logs/enabled", "true"},
	                                                    {"event-logs/logger", "flexiapi"},
	                                                    {"event-logs/flexiapi-host", "127.0.0.1"},
	                                                    {"event-logs/flexiapi-port", to_string(port)},
	                                                    {"event-logs/flexiapi-prefix", "api/stats"},
	                                                    {"event-logs/flexiapi-api-key", "aRandomApiToken"},
	                                                    {"global::flexiapi/api-key", "aRandomApiToken"}};
	const string expectedAuthority = "127.0.0.1:"s + to_string(port);
	const auto proxy = makeAndStartProxy(customConfigs);
	startCallAndCheckAuthority(proxy, flexiapiServer, eventLogRequestsReceivedCount, expectedAuthority);
}

void startLogWriterMissingApikey() {
	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	// Event-logs parameters are used as global::flexiapi/api-key is missing.
	std::map<std::string, std::string> customConfigs = {
	    {"event-logs/enabled", "true"},
	    {"event-logs/logger", "flexiapi"},
	    {"event-logs/flexiapi-host", "127.0.0.1"},
	    {"event-logs/flexiapi-port", to_string(port)},
	    {"event-logs/flexiapi-prefix", "api/stats"},
	    {"event-logs/flexiapi-api-key", "aRandomApiToken"},
	    {"global::flexiapi/url", "https://localhost:"s + to_string(port)}};
	const string expectedAuthority = "127.0.0.1:"s + to_string(port);
	const auto proxy = makeAndStartProxy(customConfigs);
	startCallAndCheckAuthority(proxy, flexiapiServer, eventLogRequestsReceivedCount, expectedAuthority);
}

void startLogWriterGlobalOverrides() {
	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	// global::flexiapi parameters overrides those from event-logs section.
	std::map<std::string, std::string> customConfigs = {
	    {"event-logs/enabled", "true"},
	    {"event-logs/logger", "flexiapi"},
	    {"event-logs/flexiapi-host", "127.0.0.1"},
	    {"event-logs/flexiapi-port", to_string(port)},
	    {"event-logs/flexiapi-prefix", "api/stats"},
	    {"event-logs/flexiapi-api-key", "aRandomApiToken"},
	    {"global::flexiapi/url", "https://localhost:"s + to_string(port)},
	    {"global::flexiapi/api-key", "aRandomApiToken"}};
	const string expectedAuthority = "localhost:"s + to_string(port);
	const auto proxy = makeAndStartProxy(customConfigs);
	startCallAndCheckAuthority(proxy, flexiapiServer, eventLogRequestsReceivedCount, expectedAuthority);
}

void callStartedAndEnded(std::map<std::string, std::string>& customConfigs) {
	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	string authority;
	BC_HARD_ASSERT_TRUE(port > -1);
	if (customConfigs.find("event-logs/flexiapi-port") != customConfigs.end()) {
		customConfigs["event-logs/flexiapi-port"] = to_string(port);
		authority = customConfigs["event-logs/flexiapi-host"] + ":" + to_string(port);
	}
	if (auto it = customConfigs.find("global::flexiapi/url"); it != customConfigs.end()) {
		it->second += ":" + to_string(port);
		authority = it->second.substr(8);
	}

	// See makeAndStartProxy for event-log configuration
	const auto proxy = makeAndStartProxy(customConfigs);

	const ClientBuilder builder{proxy->getAgent()};
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	auto tony = builder.build(expectedFrom);
	auto mike = builder.build(expectedTo);
	const auto expectedDeviceId = mike.getGruu();

	const auto expectedCallId = tony.call(mike)->getCallLog()->getCallId();
	// expect to received 3 event logs: INVITE, 180 Ringing, 200 OK

	BcAssert asserter{[&proxy] { proxy->getRoot()->step(10ms); }};
	BC_HARD_ASSERT_TRUE(
	    asserter.iterateUpTo(5, [&eventLogRequestsReceivedCount] { return eventLogRequestsReceivedCount == 3; }));

	const auto startedEvent = flexiapiServer.popRequestReceived();
	BC_HARD_ASSERT(startedEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(startedEvent->method, "POST");
	BC_ASSERT_CPP_EQUAL(startedEvent->path, "/api/stats/calls");
	BC_ASSERT_CPP_EQUAL(startedEvent->authority, authority);
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
	    {"sip_call_id", expectedCallId},
	    {"conference_id", nullptr},
	    {"devices",
	     {
	         {expectedDeviceId, nullptr},
	     }},
	};
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	const auto ringingEvent = flexiapiServer.popRequestReceived();
	BC_HARD_ASSERT(ringingEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(ringingEvent->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(ringingEvent->path, "/api/stats/calls/" + logId + "/devices/" + expectedDeviceId);
	try {
		actualJson = json::parse(ringingEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	BC_ASSERT_TRUE(actualJson.contains("rang_at"));
	const auto acceptedEvent = flexiapiServer.popRequestReceived();
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
	eventLogRequestsReceivedCount = 0;

	tony.endCurrentCall(mike);

	BC_HARD_ASSERT_TRUE(
	    asserter.iterateUpTo(10, [&eventLogRequestsReceivedCount] { return eventLogRequestsReceivedCount == 1; }));

	const auto endedEvent = flexiapiServer.popRequestReceived();
	BC_ASSERT_CPP_EQUAL(endedEvent->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(endedEvent->path, "/api/stats/calls/" + logId);
	try {
		actualJson = json::parse(endedEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	BC_ASSERT_TRUE(actualJson.contains("ended_at"));
}

void callStartedAndEndedWithEventLogConfig() {
	std::map<std::string, std::string> customConfigs = {
	    {"event-logs/enabled", "true"},
	    {"event-logs/logger", "flexiapi"},
	    {"event-logs/flexiapi-host", "127.0.0.1"},
	    {"event-logs/flexiapi-port", ""},
	    {"event-logs/flexiapi-prefix", "api/stats"},
	    {"event-logs/flexiapi-api-key", "aRandomApiToken"},
	};
	callStartedAndEnded(customConfigs);
}

void callStartedAndEndedWithGlobalConfig() {
	std::map<std::string, std::string> customConfigs = {
	    {"event-logs/enabled", "true"},
	    {"event-logs/logger", "flexiapi"},
	    {"global::flexiapi/url", "https://localhost"},
	    {"global::flexiapi/api-key", "aRandomApiToken"},
	};
	callStartedAndEnded(customConfigs);
}

void messageSentAndReceived() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	agent->setEventLogWriter(std::make_unique<FlexiStatsEventLogWriter>(
	    getRestClient(*agent->getRoot(), "127.0.0.1", port, "aRandomApiToken"), "/api/stats/"));
	ClientBuilder builder{proxy->getAgent()};
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	const auto tony = builder.build(expectedFrom);
	// Send IMDNs as CPIM so as to camouflage the content type.
	// The stats writer will have to rely on the priority to determine whether to log the message or not.
	// Note: no IMDN are sent anymore since the SDk is built without ENABLE_ADVANCED_IM.
	const auto mike = builder.build(expectedTo);
	const auto directChat = tony.chatroomBuilder().build({mike.getMe()});
	const auto& forkMessageContextsStats =
	    dynamic_cast<ModuleRouter&>(*agent->findModuleByRole("Router")).mStats.mForkStats->mCountMessageForks;
	BC_HARD_ASSERT_CPP_EQUAL(forkMessageContextsStats->start->read(), 0);
	BC_HARD_ASSERT_CPP_EQUAL(forkMessageContextsStats->finish->read(), 0);
	const auto expectedDeviceId = mike.getGruu();
	CoreAssert asserter{tony, mike, agent};
	const auto before = chrono::system_clock::now();

	directChat->createMessageFromUtf8("We're out of lemon tea...")->send();
	asserter
	    .iterateUpTo(12,
	                 [&forkMessageContextsStats, &eventLogRequestsReceivedCount]() {
		                 FAIL_IF(eventLogRequestsReceivedCount < 2 /* Sent + Delivered */);
		                 const auto started = forkMessageContextsStats->start->read();
		                 FAIL_IF(started < 1 /* 1 MSG */);
		                 FAIL_IF(forkMessageContextsStats->finish->read() != started);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(eventLogRequestsReceivedCount, 2);
	const auto sentEvent = flexiapiServer.popRequestReceived();
	BC_HARD_ASSERT(sentEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(sentEvent->method, "POST");
	BC_ASSERT_CPP_EQUAL(sentEvent->path, "/api/stats/messages");
	json actualJson;
	try {
		actualJson = json::parse(sentEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto logId = actualJson["id"].get<string>();
	actualJson.erase("id");
	const auto sentAt = actualJson["sent_at"].get<flexiapi::ISO8601Date>();
	actualJson.erase("sent_at");
	json expectedJson{
	    {"from", expectedFrom},
	    {"to",
	     {
	         {expectedTo,
	          {
	              {expectedDeviceId, nullptr},
	          }},
	     }},
	    {"conference_id", nullptr},
	    {"encrypted", false},
	};
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	BC_ASSERT_TRUE(before <= sentAt);
	const auto deliveredEvent = flexiapiServer.popRequestReceived();
	BC_HARD_ASSERT(deliveredEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(deliveredEvent->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(deliveredEvent->path,
	                    "/api/stats/messages/" + logId + "/to/" + expectedTo + "/devices/" + expectedDeviceId);
	try {
		actualJson = json::parse(deliveredEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto receivedAt = actualJson["received_at"].get<flexiapi::ISO8601Date>();
	actualJson.erase("received_at");
	expectedJson = R"(
		{
		  "last_status": 200
		})"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	BC_ASSERT_TRUE(sentAt <= receivedAt);
	const auto differentTimezone = before + 1h;
	BC_ASSERT_TRUE(receivedAt < differentTimezone);
}

void messageDeviceUnavailable() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	std::atomic_int eventLogRequestsReceivedCount{0};
	HttpMock flexiapiServer{{"/"}, &eventLogRequestsReceivedCount};
	int port = flexiapiServer.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	agent->setEventLogWriter(
	    std::make_unique<FlexiStatsEventLogWriter>(getRestClient(*agent->getRoot(), "127.0.0.1", port, "toktok"), "/"));
	const ClientBuilder builder{proxy->getAgent()};
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	const auto tony = builder.build(expectedFrom);
	const auto mikePhone = builder.build(expectedTo);
	const auto mikeDesktop = builder.build(expectedTo);
	mikeDesktop.disconnect();
	const auto directChat = tony.chatroomBuilder().build({mikePhone.getMe()});
	const auto& forkMessageContextsStats =
	    dynamic_cast<ModuleRouter&>(*agent->findModuleByRole("Router")).mStats.mForkStats->mCountMessageForks;
	const auto phoneId = mikePhone.getGruu();
	const auto desktopId = mikeDesktop.getGruu();
	CoreAssert asserter{tony, mikePhone, mikeDesktop, agent};
	const auto before = chrono::system_clock::now();

	directChat->createMessageFromUtf8("'Wish I had portal gun")->send();
	asserter
	    .iterateUpTo(
	        8,
	        [&forkMessageContextsStats, &eventLogRequestsReceivedCount]() {
		        FAIL_IF(eventLogRequestsReceivedCount < 3 /* Sent + Delivered x 2 */);
		        const auto started = forkMessageContextsStats->start->read();
		        FAIL_IF(started < 1 /* 1 MSG */);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(eventLogRequestsReceivedCount, 3);
	const auto sentEvent = flexiapiServer.popRequestReceived();
	BC_HARD_ASSERT(sentEvent != nullptr);
	BC_ASSERT_CPP_EQUAL(sentEvent->method, "POST");
	BC_ASSERT_CPP_EQUAL(sentEvent->path, "/messages");
	json actualJson;
	try {
		actualJson = json::parse(sentEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto logId = actualJson["id"].get<string>();
	actualJson.erase("id");
	const auto sentAt = actualJson["sent_at"].get<flexiapi::ISO8601Date>();
	actualJson.erase("sent_at");
	json expectedJson{
	    {"from", expectedFrom},
	    {"to",
	     {
	         {expectedTo,
	          {
	              {phoneId, nullptr},
	              {desktopId, nullptr},
	          }},
	     }},
	    {"conference_id", nullptr},
	    {"encrypted", false},
	};
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	BC_ASSERT_TRUE(before <= sentAt);
	unordered_map<string, shared_ptr<Request>> deliveredEvents{};
	auto emplaceDeliveredEvent = [&deliveredEvents](auto event) {
		BC_ASSERT(event != nullptr);
		deliveredEvents.emplace(event->path, std::move(event));
	};
	emplaceDeliveredEvent(flexiapiServer.popRequestReceived());
	emplaceDeliveredEvent(flexiapiServer.popRequestReceived());
	const auto patchMessagePrefix = "/messages/" + logId + "/to/" + expectedTo + "/devices/";
	const auto phoneEvent = deliveredEvents.find(patchMessagePrefix + phoneId);
	const auto desktopEvent = deliveredEvents.find(patchMessagePrefix + desktopId);
	BC_HARD_ASSERT_TRUE(phoneEvent != deliveredEvents.end());
	BC_HARD_ASSERT_TRUE(desktopEvent != deliveredEvents.end());
	{
		const auto& deliveredEvent = phoneEvent->second;
		BC_ASSERT_CPP_EQUAL(deliveredEvent->method, "PATCH");
		try {
			actualJson = json::parse(deliveredEvent->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		const auto receivedAt = actualJson["received_at"].get<flexiapi::ISO8601Date>();
		actualJson.erase("received_at");
		expectedJson = R"(
		{
		  "last_status": 200
		})"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
		BC_ASSERT_TRUE(sentAt <= receivedAt);
	}
	{
		const auto& deliveredEvent = desktopEvent->second;
		BC_ASSERT_CPP_EQUAL(deliveredEvent->method, "PATCH");
		try {
			actualJson = json::parse(deliveredEvent->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		const auto receivedAt = actualJson["received_at"].get<flexiapi::ISO8601Date>();
		actualJson.erase("received_at");
		expectedJson = R"(
		{
		  "last_status": 503
		})"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
		BC_ASSERT_TRUE(sentAt <= receivedAt);
	}
	eventLogRequestsReceivedCount = 0;

	mikeDesktop.reconnect();
	asserter
	    .iterateUpTo(
	        4,
	        [&forkMessageContextsStats, &eventLogRequestsReceivedCount,
	         &mikeDesktopAccount = *mikeDesktop.getAccount()]() {
		        FAIL_IF(mikeDesktopAccount.getState() != linphone::RegistrationState::Ok);
		        FAIL_IF(eventLogRequestsReceivedCount < 1);
		        const auto started = forkMessageContextsStats->start->read();
		        FAIL_IF(started < 1);
		        FAIL_IF(forkMessageContextsStats->finish->read() != started);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(eventLogRequestsReceivedCount, 1);
	{
		const auto& deliveredEvent = flexiapiServer.popRequestReceived();
		BC_ASSERT_CPP_EQUAL(deliveredEvent->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(deliveredEvent->path, patchMessagePrefix + desktopId);
		try {
			actualJson = json::parse(deliveredEvent->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		const auto receivedAt = actualJson["received_at"].get<flexiapi::ISO8601Date>();
		actualJson.erase("received_at");
		expectedJson = R"(
		{
		  "last_status": 200
		})"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
		BC_ASSERT_TRUE(sentAt <= receivedAt);
		const auto differentTimezone = before + 1h;
		BC_ASSERT_TRUE(receivedAt < differentTimezone);
	}
}

namespace {

TestSuite _{
    "FlexiStatsEventLogWriter",
    {
        CLASSY_TEST(startLogWriter),
        CLASSY_TEST(startLogWriterMissingUrl),
        CLASSY_TEST(startLogWriterMissingApikey),
        CLASSY_TEST(startLogWriterGlobalOverrides),
        CLASSY_TEST(callStartedAndEndedWithGlobalConfig),
        CLASSY_TEST(callStartedAndEndedWithEventLogConfig),
        CLASSY_TEST(messageSentAndReceived),
        CLASSY_TEST(messageDeviceUnavailable),
    },
    Hooks{}
        .beforeSuite([] {
	        sDbServer.emplace();
	        sDbServer->waitReady();
	        return 0;
        })
        .beforeEach([] { sDbServer->clear(); })
        .afterSuite([] {
	        sDbServer.reset();
	        return 0;
        }),
};

} // namespace
} // namespace flexisip::tester::eventlogs