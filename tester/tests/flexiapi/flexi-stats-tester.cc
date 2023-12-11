/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "flexiapi/flexi-stats.hh"

#include "flexisip/utils/sip-uri.hh"
#include "lib/nlohmann-json-3-11-2/json.hpp"
#include "utils/asserts.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;
using namespace nlohmann;

namespace flexisip {
using namespace flexiapi;
namespace tester::http_mock {

time_t getTestDate() {
	struct tm tm;
	tm.tm_year = 2017 - 1900;
	tm.tm_mon = 7 - 1;
	tm.tm_mday = 21;
	tm.tm_hour = 17;
	tm.tm_min = 32;
	tm.tm_sec = 28;
	tm.tm_isdst = 0;
	return timegm(&tm);
	/* return time_t for 2017-07-21T17:32:28Z */
}

time_t getTestDateAfter() {
	struct tm tm;
	tm.tm_year = 2017 - 1900;
	tm.tm_mon = 7 - 1;
	tm.tm_mday = 21;
	tm.tm_hour = 18;
	tm.tm_min = 32;
	tm.tm_sec = 28;
	tm.tm_isdst = 0;
	return timegm(&tm);
	/* return time_t for 2017-07-21T18:32:28Z */
}

// ####################################################################################################################
// ################################################### ABSTRACT TEST CLASS ############################################
// ####################################################################################################################

class FlexiStatsTest : public Test {
public:
	void operator()() override {
		HttpMock httpMock{{"/"}, &mRequestReceivedCount};
		int port = httpMock.serveAsync();
		BC_HARD_ASSERT_TRUE(port > -1);

		FlexiStats flexiStats{mRoot, "localhost", to_string(port), "api////stats//", "aRandomApiToken"};

		sendRequest(flexiStats);

		BcAssert asserter{[this] { mRoot.step(1ms); }};
		BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(10, [this] { return mRequestReceivedCount == 1; }));

		httpMock.forceCloseServer();
		mRoot.step(10ms); // needed to acknowledge mock server closing

		BC_HARD_ASSERT_CPP_EQUAL(mRequestReceivedCount, 1);
		const auto actualRequest = httpMock.popRequestReceived();
		BC_HARD_ASSERT(actualRequest != nullptr);

		customAssert(actualRequest);
		const auto& headers = actualRequest->headers;
		BC_ASSERT_CPP_EQUAL(headers.size(), 4);
		auto header = headers.find("x-api-key");
		BC_HARD_ASSERT_TRUE(header != headers.end());
		BC_ASSERT_CPP_EQUAL(header->second.value, "aRandomApiToken");
		header = headers.find("accept");
		BC_HARD_ASSERT_TRUE(header != headers.end());
		BC_ASSERT_CPP_EQUAL(header->second.value, "application/json");
		header = headers.find("content-type");
		BC_HARD_ASSERT_TRUE(header != headers.end());
		BC_ASSERT_CPP_EQUAL(header->second.value, "application/json");
		header = headers.find("content-length");
		BC_HARD_ASSERT_TRUE(header != headers.end());
		BC_ASSERT_CPP_EQUAL(header->second.value, to_string(actualRequest->body.size()));
	}

protected:
	virtual void sendRequest(FlexiStats& flexiStats) = 0;
	virtual void customAssert(const shared_ptr<Request>& actualRequest) = 0;

	std::atomic_int mRequestReceivedCount = 0;

private:
	sofiasip::SuRoot mRoot{};
};

// ####################################################################################################################
// ################################################### ACTUAL TESTS ###################################################
// ####################################################################################################################

class PostMessageFullTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		ToParam to{
		    {ApiFormattedUri(*SipUri("sip:user1@domain.org").get()),
		     MessageDevices{
		         {"device_id_1", MessageDeviceResponse{200, getTestDate()}},
		         {"device_id_2", MessageDeviceResponse{408, getTestDateAfter()}},
		         {"device_id_3", nullopt},
		     }},
		    {ApiFormattedUri(*SipUri("sip:user2@domain.org").get()),
		     MessageDevices{
		         {"device_id_1", MessageDeviceResponse{503, getTestDate()}},
		         {"device_id_2", nullopt},
		     }},
		};

		Message message{"84c937d1-f1b5-475d-adb7-b41b78b078d4",
		                *SipUri("sip:user@sip.linphone.org").get(),
		                to,
		                getTestDate(),
		                true,
		                "iHVDMq6MxSKp60bT"};

		flexiStats.postMessage(message);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/messages");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "id": "84c937d1-f1b5-475d-adb7-b41b78b078d4",
		  "from": "user@sip.linphone.org",
		  "to": {
			"user1@domain.org": {
			  "device_id_1": {
				"last_status": 200,
				"received_at": "2017-07-21T17:32:28Z"
			  },
			  "device_id_2": {
				"last_status": 408,
				"received_at": "2017-07-21T18:32:28Z"
			  },
			  "device_id_3": null
			},
			"user2@domain.org": {
			  "device_id_1": {
				"last_status": 503,
				"received_at": "2017-07-21T17:32:28Z"
			  },
			  "device_id_2": null
			}
		  },
		  "sent_at": "2017-07-21T17:32:28Z",
		  "encrypted": true,
		  "conference_id": "iHVDMq6MxSKp60bT"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class PostMessageMinimalTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		Message message{"84c937d1-f1b5-475d-adb7-b41b78b078d4",
		                *SipUri("sip:user@sip.linphone.org").get(),
		                ToParam{},
		                getTestDate(),
		                false,
		                nullopt};

		flexiStats.postMessage(message);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/messages");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "id": "84c937d1-f1b5-475d-adb7-b41b78b078d4",
		  "from": "user@sip.linphone.org",
		  "to": {},
		  "sent_at": "2017-07-21T17:32:28Z",
		  "encrypted": false,
		  "conference_id": null
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class NotifyMessageDeviceResponseTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		MessageDeviceResponse messageDeviceResponse{200, getTestDate()};

		flexiStats.notifyMessageDeviceResponse("84c937d1", *SipUri("sip:user1@domain.org").get(), "device_id",
		                                       messageDeviceResponse);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/messages/84c937d1/to/user1@domain.org/devices/device_id");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "last_status": 200,
		  "received_at": "2017-07-21T17:32:28Z"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class PostCallFullTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		CallDevices callDevices{
		    {"device_id_1", CallDeviceState{getTestDate(), Terminated{getTestDateAfter(), TerminatedState::ACCEPTED}}},
		    {"device_id_2",
		     CallDeviceState{getTestDate(), Terminated{getTestDateAfter(), TerminatedState::ACCEPTED_ELSEWHERE}}},
		    {"device_id_3", nullopt},
		};

		Call call{"4722b0233fd8cafad3cdcafe5510fe57",
		          *SipUri("sip:user@sip.linphone.org").get(),
		          *SipUri("sip:user@sip.linphone.org").get(),
		          callDevices,
		          getTestDate(),
		          "iHVDMq6MxSKp60bT",
		          getTestDateAfter()};

		flexiStats.postCall(call);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "id": "4722b0233fd8cafad3cdcafe5510fe57",
		  "from": "user@sip.linphone.org",
		  "to": "user@sip.linphone.org",
		  "devices": {
			"device_id_1": {
			  "rang_at": "2017-07-21T17:32:28Z",
			  "invite_terminated": {
				"at": "2017-07-21T18:32:28Z",
				"state": "accepted"
			  }
			},
			"device_id_2": {
			  "rang_at": "2017-07-21T17:32:28Z",
			  "invite_terminated": {
				"at": "2017-07-21T18:32:28Z",
				"state": "accepted_elsewhere"
			  }
			},
			"device_id_3": null
		  },
		  "initiated_at": "2017-07-21T17:32:28Z",
		  "ended_at": "2017-07-21T18:32:28Z",
		  "conference_id": "iHVDMq6MxSKp60bT"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class PostCallMinimalTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		Call call{"4722b0233fd8cafad3cdcafe5510fe57",
		          *SipUri("sip:user@sip.linphone.org").get(),
		          *SipUri("sip:user@sip.linphone.org").get(),
		          CallDevices{},
		          getTestDate(),
		          nullopt,
		          nullopt};

		flexiStats.postCall(call);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "id": "4722b0233fd8cafad3cdcafe5510fe57",
		  "from": "user@sip.linphone.org",
		  "to": "user@sip.linphone.org",
		  "devices": {},
		  "initiated_at": "2017-07-21T17:32:28Z",
		  "ended_at": null,
		  "conference_id": null
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class UpdateCallDeviceStateFullTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		CallDeviceState callDeviceState{getTestDate(), Terminated{getTestDateAfter(), TerminatedState::ERROR}};

		flexiStats.updateCallDeviceState("4722b0233", "device_id", callDeviceState);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "rang_at": "2017-07-21T17:32:28Z",
		  "invite_terminated": {
			"at": "2017-07-21T18:32:28Z",
			"state": "error"
		  }
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class UpdateCallDeviceStateRangOnlyTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		CallDeviceState callDeviceState{getTestDate(), nullopt};

		flexiStats.updateCallDeviceState("4722b0233", "device_id_1", callDeviceState);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id_1");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "rang_at": "2017-07-21T17:32:28Z"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class UpdateCallDeviceStateTerminatedOnlyTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		CallDeviceState callDeviceState{nullopt, Terminated{getTestDate(), TerminatedState::DECLINED}};

		flexiStats.updateCallDeviceState("4722b0233", "device_id_1", callDeviceState);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id_1");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
		  "invite_terminated": {
			"at": "2017-07-21T17:32:28Z",
			"state": "declined"
		  }
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class UpdateCallDeviceStateEmptyTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		CallDeviceState callDeviceState{nullopt, nullopt};

		flexiStats.updateCallDeviceState("4722b0233", "device_id_1", callDeviceState);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id_1");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"({})"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class UpdateCallStateTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		flexiStats.updateCallState("4722b0233", getTestDateAfter());
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
			"ended_at": "2017-07-21T18:32:28Z"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class PostConferenceFullTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		Conference conference{"iHVDMq6MxSKp60bT", getTestDate(), "string", getTestDateAfter()};

		flexiStats.postConference(conference);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/conferences");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
			"id": "iHVDMq6MxSKp60bT",
			"created_at": "2017-07-21T17:32:28Z",
			"ended_at": "2017-07-21T18:32:28Z",
			"schedule": "string"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class PostConferenceMinimalTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		Conference conference{"iHVDMq6MxSKp60bT", getTestDate(), nullopt, nullopt};

		flexiStats.postConference(conference);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/conferences");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
			"id": "iHVDMq6MxSKp60bT",
			"created_at": "2017-07-21T17:32:28Z",
			"ended_at": null,
			"schedule": null
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class NotifyConferenceEndedTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		flexiStats.notifyConferenceEnded("iHVDMq6MxSKp60bT", getTestDate());
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/conferences/iHVDMq6MxSKp60bT");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
			"ended_at": "2017-07-21T17:32:28Z"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class ConferenceAddParticipantEventTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		ParticipantEvent participantEvent{ParticipantEventType::ADDED, getTestDate()};
		flexiStats.conferenceAddParticipantEvent("iHVDMq6MxSKp60bT", *SipUri("sip:user1@domain.org").get(),
		                                         participantEvent);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path,
		                    "/api/stats/conferences/iHVDMq6MxSKp60bT/participants/user1@domain.org/events");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
			"type": "added",
			"at": "2017-07-21T17:32:28Z"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

class ConferenceAddParticipantDeviceEventTest : public FlexiStatsTest {
protected:
	void sendRequest(FlexiStats& flexiStats) override {
		ParticipantDeviceEvent participantDeviceEvent{ParticipantDeviceEventType::INVITED, getTestDate()};
		flexiStats.conferenceAddParticipantDeviceEvent("iHVDMq6MxSKp60bT", *SipUri("sip:user1@domain.org").get(),
		                                               "device_id", participantDeviceEvent);
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(
		    actualRequest->path,
		    "/api/stats/conferences/iHVDMq6MxSKp60bT/participants/user1@domain.org/devices/device_id/events");
		json actualJson;
		try {
			actualJson = json::parse(actualRequest->body);
		} catch (const exception&) {
			BC_FAIL("json::parse exception with received body");
		}
		auto expectedJson = R"(
		{
			"type": "invited",
			"at": "2017-07-21T17:32:28Z"
		}
		)"_json;
		BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
	}
};

namespace {
TestSuite _("FlexiStats client unit tests",
            {
                CLASSY_TEST(PostMessageFullTest),
                CLASSY_TEST(PostMessageMinimalTest),
                CLASSY_TEST(NotifyMessageDeviceResponseTest),
                CLASSY_TEST(PostCallFullTest),
                CLASSY_TEST(PostCallMinimalTest),
                CLASSY_TEST(UpdateCallDeviceStateFullTest),
                CLASSY_TEST(UpdateCallDeviceStateRangOnlyTest),
                CLASSY_TEST(UpdateCallDeviceStateTerminatedOnlyTest),
                CLASSY_TEST(UpdateCallDeviceStateEmptyTest),
                CLASSY_TEST(UpdateCallStateTest),
                CLASSY_TEST(PostConferenceFullTest),
                CLASSY_TEST(PostConferenceMinimalTest),
                CLASSY_TEST(PostConferenceMinimalTest),
                CLASSY_TEST(NotifyConferenceEndedTest),
                CLASSY_TEST(ConferenceAddParticipantEventTest),
                CLASSY_TEST(ConferenceAddParticipantDeviceEventTest),
            });
} // namespace

} // namespace tester::http_mock
} // namespace flexisip
