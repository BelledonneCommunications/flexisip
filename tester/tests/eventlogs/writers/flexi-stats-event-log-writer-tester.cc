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

#include "eventlogs/writers/flexi-stats-event-log-writer.hh"

#include <atomic>
#include <memory>
#include <regex>
#include <unordered_map>

#include "bctoolbox/tester.h"
#include "flexisip/configmanager.hh"
#include "flexisip/module-router.hh"
#include "linphone++/enums.hh"

#include "flexiapi/schemas/iso-8601-date.hh"
#include "utils/asserts.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/eventlogs/event-logs.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/mysql-server.hh"
#include "utils/proxy-server.hh"
#include "utils/test-conference-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace nlohmann;

namespace flexisip::tester::eventlogs {
using namespace flexisip::tester::http_mock;

void callStartedAndEnded() {
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
	                                      {"event-logs/flexiapi-api-key", "aRandomApiToken"}});
	const auto builder = proxy->clientBuilder();
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	auto tony = builder.build(expectedFrom);
	auto mike = builder.build(expectedTo);
	const auto expectedDeviceId = mike.getGruu();

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

void callToConference() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};
	int port = httpMock.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	agent->setEventLogWriter(std::make_unique<FlexiStatsEventLogWriter>(*agent->getRoot(), "localhost", to_string(port),
	                                                                    "", "aRandomApiToken"));
	const auto builder = proxy->clientBuilder();
	const auto johan = builder.build("sip:johan@sip.example.org");
	const string expectedConferenceId = "expected-conf-id";
	const auto chatroom = "sip:chatroom-" + expectedConferenceId + "@sip.example.org";
	const auto fakeConfServer = builder.build(chatroom);
	CoreAssert asserter{johan, fakeConfServer, agent};

	johan.invite(chatroom);
	BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(
	    4, [&requestsReceivedCount] { return 0 < requestsReceivedCount; }, 1s));

	const auto startedEvent = httpMock.popRequestReceived();
	json actualJson;
	try {
		actualJson = json::parse(startedEvent->body);
	} catch (const exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	BC_ASSERT_CPP_EQUAL(actualJson.at("conference_id"), expectedConferenceId);
}

void messageSentAndReceived() {
	const auto proxy = makeAndStartProxy();
	const auto& agent = proxy->getAgent();
	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};
	int port = httpMock.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	agent->setEventLogWriter(std::make_unique<FlexiStatsEventLogWriter>(*agent->getRoot(), "localhost", to_string(port),
	                                                                    "/api/stats/", "aRandomApiToken"));
	auto builder = proxy->clientBuilder();
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	const auto tony = builder.build(expectedFrom);
	// Send IMDNs as CPIM so as to camouflage the content type.
	// The stats writer will have to rely on the priority to determine whether to log the message or not
	const auto mike = builder.setCpimInBasicChatroom(OnOff::On).build(expectedTo);
	const auto directChat = tony.chatroomBuilder().build({mike.getMe()});
	const auto& forkMessageContextsStats =
	    dynamic_cast<ModuleRouter&>(*agent->findModule("Router")).mStats.mCountMessageForks;
	BC_HARD_ASSERT_CPP_EQUAL(forkMessageContextsStats->start->read(), 0);
	BC_HARD_ASSERT_CPP_EQUAL(forkMessageContextsStats->finish->read(), 0);
	const auto expectedDeviceId = mike.getGruu();
	CoreAssert asserter{tony, mike, agent};
	const auto before = chrono::system_clock::now();

	directChat->createMessageFromUtf8("We're out of lemon tea...")->send();
	asserter
	    .iterateUpTo(6,
	                 [&forkMessageContextsStats, &requestsReceivedCount]() {
		                 FAIL_IF(requestsReceivedCount < 2 /* Sent + Delivered */);
		                 const auto started = forkMessageContextsStats->start->read();
		                 FAIL_IF(started < 2 /* MSG + IMDN */);
		                 FAIL_IF(forkMessageContextsStats->finish->read() != started);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(requestsReceivedCount, 2);
	const auto sentEvent = httpMock.popRequestReceived();
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
	const auto deliveredEvent = httpMock.popRequestReceived();
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
	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};
	int port = httpMock.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);
	agent->setEventLogWriter(
	    std::make_unique<FlexiStatsEventLogWriter>(*agent->getRoot(), "localhost", to_string(port), "/", "toktok"));
	const auto builder = proxy->clientBuilder();
	const string expectedFrom = "tony@sip.example.org";
	const string expectedTo = "mike@sip.example.org";
	const auto tony = builder.build(expectedFrom);
	const auto mikePhone = builder.build(expectedTo);
	const auto mikeDesktop = builder.build(expectedTo);
	mikeDesktop.disconnect();
	const auto directChat = tony.chatroomBuilder().build({mikePhone.getMe()});
	const auto& forkMessageContextsStats =
	    dynamic_cast<ModuleRouter&>(*agent->findModule("Router")).mStats.mCountMessageForks;
	const auto phoneId = mikePhone.getGruu();
	const auto desktopId = mikeDesktop.getGruu();
	CoreAssert asserter{tony, mikePhone, mikeDesktop, agent};
	const auto before = chrono::system_clock::now();

	directChat->createMessageFromUtf8("'Wish I had portal gun")->send();
	asserter
	    .iterateUpTo(
	        8,
	        [&forkMessageContextsStats, &requestsReceivedCount]() {
		        FAIL_IF(requestsReceivedCount < 3 /* Sent + Delivered x 2 */);
		        const auto started = forkMessageContextsStats->start->read();
		        FAIL_IF(started < 2 /* MSG + IMDN */);
		        FAIL_IF(forkMessageContextsStats->finish->read() < 1);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(requestsReceivedCount, 3);
	const auto sentEvent = httpMock.popRequestReceived();
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
	auto emplaceDeliveredEvent = [&deliveredEvents](auto&& event) {
		BC_ASSERT(event != nullptr);
		deliveredEvents.emplace(event->path, std::move(event));
	};
	emplaceDeliveredEvent(httpMock.popRequestReceived());
	emplaceDeliveredEvent(httpMock.popRequestReceived());
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
	requestsReceivedCount = 0;

	mikeDesktop.reconnect();
	asserter
	    .iterateUpTo(
	        4,
	        [&forkMessageContextsStats, &requestsReceivedCount, &mikeDesktopAccount = *mikeDesktop.getAccount()]() {
		        FAIL_IF(mikeDesktopAccount.getState() != linphone::RegistrationState::Ok);
		        FAIL_IF(requestsReceivedCount < 1);
		        const auto started = forkMessageContextsStats->start->read();
		        FAIL_IF(started < 3);
		        FAIL_IF(forkMessageContextsStats->finish->read() != started);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(requestsReceivedCount, 1);
	{
		const auto& deliveredEvent = httpMock.popRequestReceived();
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

void messageToChatroomClearText() {
	const MysqlServer mysqlServer{};
	const string confFactoryUri = "sip:conference-factory@sip.example.org";
	const auto proxy = makeAndStartProxy({
	    {"conference-server/conference-factory-uris", confFactoryUri},
	    // `sqlite` breaks on CentOS7 with inexplicable disk I/O errors
	    {"conference-server/database-backend", "mysql"},
	    {"conference-server/database-connection-string", mysqlServer.connectionString()},
	});
	const auto& agent = proxy->getAgent();
	GenericManager::get()
	    ->getRoot()
	    ->get<GenericStruct>("conference-server")
	    ->get<ConfigValue>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy->getFirstPort() + ";transport=tcp");
	auto builder = proxy->clientBuilder();
	builder.setConferenceFactoryUri(confFactoryUri);
	builder.setLimeX3DH(OnOff::Off);
	const string expectedFrom = "clemence@sip.example.org";
	const string expectedTos[] = {"pauline@sip.example.org", "tony@sip.example.org", "mike@sip.example.org"};
	constexpr int recipientCount = sizeof(expectedTos) / sizeof(expectedTos[0]);
	const auto clemence = builder.build(expectedFrom);
	const auto pauline = builder.build(expectedTos[0]);
	const auto tony = builder.build(expectedTos[1]);
	const auto mike = builder.build(expectedTos[2]);
	CoreAssert asserter{clemence, pauline, tony, mike, agent};
	const auto clemChat = clemence.chatroomBuilder()
	                          .setBackend(linphone::ChatRoomBackend::FlexisipChat)
	                          .setSubject("GYM")
	                          .build({pauline.getMe(), tony.getMe(), mike.getMe()});
	BC_HARD_ASSERT_TRUE(clemChat != nullptr);
	std::atomic_int requestsReceivedCount{0};
	HttpMock httpMock{{"/"}, &requestsReceivedCount};
	int port = httpMock.serveAsync();
	agent->setEventLogWriter(
	    std::make_unique<FlexiStatsEventLogWriter>(*agent->getRoot(), "localhost", to_string(port), "/", "toktok"));
	mysqlServer.waitReady();
	const TestConferenceServer confServer{*agent};
	const auto before = chrono::system_clock::now();

	clemChat->createMessageFromUtf8("💃🏼")->send();
	asserter
	    .iterateUpTo(0x10,
	                 [&requestsReceivedCount]() {
		                 FAIL_IF(requestsReceivedCount < 1 /* sent */ + recipientCount);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	const auto sentEvent = httpMock.popRequestReceived();
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
	    {"to", unordered_map<string, nullptr_t>{}},
	    {"conference_id", clemChat->getConferenceAddress()->getUsername().substr(sizeof("chatroom-") - 1)},
	    {"encrypted", false},
	};
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	BC_ASSERT_TRUE(before <= sentAt);
	unordered_map<string, shared_ptr<Request>> deliveredEvents{};
	const regex extractEventIdAndDeviceFromPath{R"regex(/messages/(.+)/to/(.+)/devices/.+)regex"};
	for (auto _ = 0; _ < recipientCount; ++_) {
		auto event = httpMock.popRequestReceived();
		BC_ASSERT(event != nullptr);
		std::smatch match{};
		BC_ASSERT_TRUE(std::regex_match(event->path, match, extractEventIdAndDeviceFromPath));
		BC_HARD_ASSERT_CPP_EQUAL(match.size(), 3);
		BC_ASSERT_CPP_EQUAL(match[1], logId);
		deliveredEvents.emplace(match[2], std::move(event));
	}
	for (const auto& expectedTo : expectedTos) {
		const auto& deliveredEvent = deliveredEvents[expectedTo];
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
}

namespace {
TestSuite _("FlexiStatsEventLogWriter",
            {
                CLASSY_TEST(callStartedAndEnded),
                CLASSY_TEST(callToConference),
                CLASSY_TEST(messageSentAndReceived),
                CLASSY_TEST(messageDeviceUnavailable),
                CLASSY_TEST(messageToChatroomClearText),
            });
}

} // namespace flexisip::tester::eventlogs
