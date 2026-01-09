/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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
#include "utils/core-assert.hh"
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
	tm tm{
	    .tm_sec = 28,
	    .tm_min = 32,
	    .tm_hour = 17,
	    .tm_mday = 21,
	    .tm_mon = 7 - 1,
	    .tm_year = 2017 - 1900,
	    .tm_isdst = 0,
	};
	return timegm(&tm);
	/* return time_t for 2017-07-21T17:32:28Z */
}

time_t getTestDateAfter() {
	tm tm{
	    .tm_sec = 28,
	    .tm_min = 32,
	    .tm_hour = 18,
	    .tm_mday = 21,
	    .tm_mon = 7 - 1,
	    .tm_year = 2017 - 1900,
	    .tm_isdst = 0,
	};
	return timegm(&tm);
	/* return time_t for 2017-07-21T18:32:28Z */
}

// ####################################################################################################################
// ################################################### Global test pattern ############################################
// ####################################################################################################################

using SendReqFunc = function<void(FlexiStats&)>;
using CustomAssertFunc = function<void(const vector<shared_ptr<Request>>& actualRequests)>;

void flexiStatTestFunc(const SendReqFunc& sendRequest,
                       const CustomAssertFunc& customAssert,
                       int requestReceivedExpectedCount = 1) {
	sofiasip::SuRoot mRoot{};
	std::atomic_int mRequestReceivedCount{0};

	HttpMock httpMock{{"/"}, &mRequestReceivedCount};
	int port = httpMock.serveAsync();
	BC_HARD_ASSERT_TRUE(port > -1);

	FlexiStats flexiStats{mRoot, "127.0.0.1", to_string(port), "api////stats//", "aRandomApiToken"};

	sendRequest(flexiStats);

	CoreAssert asserter{mRoot};
	asserter
	    .wait([&mRequestReceivedCount, &requestReceivedExpectedCount] {
		    return LOOP_ASSERTION(mRequestReceivedCount == requestReceivedExpectedCount);
	    })
	    .assert_passed();
	BC_HARD_ASSERT_CPP_EQUAL(mRequestReceivedCount, requestReceivedExpectedCount);

	httpMock.forceCloseServer();
	mRoot.step(10ms); // needed to acknowledge mock server closing

	BC_HARD_ASSERT_CPP_EQUAL(mRequestReceivedCount, requestReceivedExpectedCount);
	vector<shared_ptr<Request>> actualRequests;
	while (auto actualRequest = httpMock.popRequestReceived()) {
		actualRequests.emplace_back(actualRequest);
	}
	BC_HARD_ASSERT_CPP_EQUAL(actualRequests.size(), requestReceivedExpectedCount);
	customAssert(actualRequests);

	for (const auto& actualRequest : actualRequests) {
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
}

// ####################################################################################################################
// ################################################### ACTUAL TESTS ###################################################
// ####################################################################################################################

void postMessageFullSendRequest(FlexiStats& flexiStats) {
	const ToParam to{
	    {
	        ApiFormattedUri(*SipUri("sip:user1@domain.org").get()),
	        MessageDevices{
	            {"device_id_1", MessageDeviceResponse{200, getTestDate()}},
	            {"device_id_2", MessageDeviceResponse{408, getTestDateAfter()}},
	            {"device_id_3", nullopt},
	        },
	    },
	    {
	        ApiFormattedUri(*SipUri("sip:user2@domain.org").get()),
	        MessageDevices{
	            {"device_id_1", MessageDeviceResponse{503, getTestDate()}},
	            {"device_id_2", nullopt},
	        },
	    },
	};

	const Message message{"84c937d1",        *SipUri("sip:user@sip.linphone.org").get(), to, getTestDate(), true,
	                      "iHVDMq6MxSKp60bT"};

	flexiStats.postMessage(message);
}
void postMessageFullCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/messages");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
		{
		  "id": "84c937d1",
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
void postMessageFullTest() {
	flexiStatTestFunc(postMessageFullSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		postMessageFullCustomAssert(actualRequests[0]);
	});
}

void postMessageMinimalRequest(FlexiStats& flexiStats) {
	const Message message{"84c937d1-f1b5-475d-adb7-b41b78b078d4",
	                      *SipUri("sip:user@sip.linphone.org").get(),
	                      ToParam{},
	                      getTestDate(),
	                      false,
	                      nullopt};

	flexiStats.postMessage(message);
}
void postMessageMinimalCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/messages");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
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
void postMessageMinimalTest() {
	flexiStatTestFunc(postMessageMinimalRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		postMessageMinimalCustomAssert(actualRequests[0]);
	});
}

void notifyMessageDeviceResponseSendRequest(FlexiStats& flexiStats) {
	const MessageDeviceResponse messageDeviceResponse{200, getTestDate()};

	flexiStats.notifyMessageDeviceResponse("84c937d1", *SipUri("sip:user1@domain.org").get(), "device_id",
	                                       messageDeviceResponse);
}
void notifyMessageDeviceResponseCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/messages/84c937d1/to/user1@domain.org/devices/device_id");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
		{
		  "last_status": 200,
		  "received_at": "2017-07-21T17:32:28Z"
		}
		)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void notifyMessageDeviceResponseTest() {
	flexiStatTestFunc(notifyMessageDeviceResponseSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		notifyMessageDeviceResponseCustomAssert(actualRequests[0]);
	});
}

void messageMultiTest() {
	auto sendRequest = [](FlexiStats& flexiStats) {
		postMessageFullSendRequest(flexiStats);
		notifyMessageDeviceResponseSendRequest(flexiStats);
	};
	auto customAssert = [](const vector<shared_ptr<Request>>& actualRequests) {
		postMessageFullCustomAssert(actualRequests[0]);
		notifyMessageDeviceResponseCustomAssert(actualRequests[1]);
	};

	flexiStatTestFunc(sendRequest, customAssert, 2);
}

void postCallFullSendRequest(FlexiStats& flexiStats) {
	const CallDevices callDevices{
	    {"device_id_1", CallDeviceState{getTestDate(), Terminated{getTestDateAfter(), TerminatedState::ACCEPTED}}},
	    {"device_id_2",
	     CallDeviceState{getTestDate(), Terminated{getTestDateAfter(), TerminatedState::ACCEPTED_ELSEWHERE}}},
	    {"device_id_3", nullopt},
	};

	const Call call{"4722b0233",
	                "stub-call-id",
	                *SipUri("sip:user@sip.linphone.org").get(),
	                *SipUri("sip:user@sip.linphone.org").get(),
	                callDevices,
	                getTestDate(),
	                "iHVDMq6MxSKp60bT",
	                getTestDateAfter()};

	flexiStats.postCall(call);
}
void postCallFullCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
		{
		  "id": "4722b0233",
		  "sip_call_id": "stub-call-id",
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
void postCallFullTest() {
	flexiStatTestFunc(postCallFullSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		postCallFullCustomAssert(actualRequests[0]);
	});
}

void postCallMinimalSendRequest(FlexiStats& flexiStats) {
	const Call call{"4722b0233fd8cafad3cdcafe5510fe57",
	                "stub-call-id",
	                *SipUri("sip:user@sip.linphone.org").get(),
	                *SipUri("sip:user@sip.linphone.org").get(),
	                CallDevices{},
	                getTestDate(),
	                nullopt,
	                nullopt};

	flexiStats.postCall(call);
}
void postCallMinimalCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
		{
		  "id": "4722b0233fd8cafad3cdcafe5510fe57",
		  "sip_call_id": "stub-call-id",
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
void postCallMinimalTest() {
	flexiStatTestFunc(postCallMinimalSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		postCallMinimalCustomAssert(actualRequests[0]);
	});
}

void updateCallDeviceStateFullSendRequest(FlexiStats& flexiStats) {
	const CallDeviceState callDeviceState{getTestDate(), Terminated{getTestDateAfter(), TerminatedState::ERROR}};

	flexiStats.updateCallDeviceState("4722b0233", "device_id", callDeviceState);
}
void updateCallDeviceStateFullCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
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
void updateCallDeviceStateFullTest() {
	flexiStatTestFunc(updateCallDeviceStateFullSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		updateCallDeviceStateFullCustomAssert(actualRequests[0]);
	});
}

void updateCallDeviceStateRangOnlySendRequest(FlexiStats& flexiStats) {
	const CallDeviceState callDeviceState{getTestDate(), nullopt};

	flexiStats.updateCallDeviceState("4722b0233", "device_id_1", callDeviceState);
}
void updateCallDeviceStateRangOnlyCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id_1");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
		{
		  "rang_at": "2017-07-21T17:32:28Z"
		}
		)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void updateCallDeviceStateRangOnlyTest() {
	flexiStatTestFunc(updateCallDeviceStateRangOnlySendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		updateCallDeviceStateRangOnlyCustomAssert(actualRequests[0]);
	});
}

void updateCallDeviceStateTerminatedOnlySendRequest(FlexiStats& flexiStats) {
	const CallDeviceState callDeviceState{nullopt, Terminated{getTestDate(), TerminatedState::DECLINED}};

	flexiStats.updateCallDeviceState("4722b0233", "device_id_1", callDeviceState);
}
void updateCallDeviceStateTerminatedOnlyCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id_1");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
		{
		  "invite_terminated": {
			"at": "2017-07-21T17:32:28Z",
			"state": "declined"
		  }
		}
		)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void updateCallDeviceStateTerminatedOnlyTest() {
	flexiStatTestFunc(updateCallDeviceStateTerminatedOnlySendRequest,
	                  [](const vector<shared_ptr<Request>>& actualRequests) {
		                  updateCallDeviceStateTerminatedOnlyCustomAssert(actualRequests[0]);
	                  });
}

void updateCallDeviceStateEmptySendRequest(FlexiStats& flexiStats) {
	const CallDeviceState callDeviceState{nullopt, nullopt};

	flexiStats.updateCallDeviceState("4722b0233", "device_id_1", callDeviceState);
}
void updateCallDeviceStateEmptyCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233/devices/device_id_1");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"({})"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void updateCallDeviceStateEmptyTest() {
	flexiStatTestFunc(updateCallDeviceStateEmptySendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		updateCallDeviceStateEmptyCustomAssert(actualRequests[0]);
	});
}

void updateCallStateSendRequest(FlexiStats& flexiStats) {
	flexiStats.updateCallState("4722b0233", getTestDateAfter());
}
void updateCallStateCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/calls/4722b0233");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
	{
		"ended_at": "2017-07-21T18:32:28Z"
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void updateCallStateTest() {
	flexiStatTestFunc(updateCallStateSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		updateCallStateCustomAssert(actualRequests[0]);
	});
}

void callMultiTest() {
	auto sendRequest = [](FlexiStats& flexiStats) {
		postCallFullSendRequest(flexiStats);
		updateCallDeviceStateFullSendRequest(flexiStats);
		updateCallDeviceStateTerminatedOnlySendRequest(flexiStats);
		updateCallStateSendRequest(flexiStats);
	};
	auto customAssert = [](const vector<shared_ptr<Request>>& actualRequests) {
		postCallFullCustomAssert(actualRequests[0]);
		updateCallDeviceStateFullCustomAssert(actualRequests[1]);
		updateCallDeviceStateTerminatedOnlyCustomAssert(actualRequests[2]);
		updateCallStateCustomAssert(actualRequests[3]);
	};

	flexiStatTestFunc(sendRequest, customAssert, 4);
}

void postConferenceFullSendRequest(FlexiStats& flexiStats) {
	const Conference conference{"iHVDMq6MxSKp60bT", getTestDate(), "string", getTestDateAfter()};

	flexiStats.postConference(conference);
}
void postConferenceFullCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/conferences");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
	{
		"id": "iHVDMq6MxSKp60bT",
		"created_at": "2017-07-21T17:32:28Z",
		"ended_at": "2017-07-21T18:32:28Z",
		"schedule": "string"
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void postConferenceFullTest() {
	flexiStatTestFunc(postConferenceFullSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		postConferenceFullCustomAssert(actualRequests[0]);
	});
}

void postConferenceMinimalSendRequest(FlexiStats& flexiStats) {
	const Conference conference{"iHVDMq6MxSKp60bT", getTestDate(), nullopt, nullopt};

	flexiStats.postConference(conference);
}
void postConferenceMinimalCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/conferences");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
	{
		"id": "iHVDMq6MxSKp60bT",
		"created_at": "2017-07-21T17:32:28Z",
		"ended_at": null,
		"schedule": null
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void postConferenceMinimalTest() {
	flexiStatTestFunc(postConferenceMinimalSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		postConferenceMinimalCustomAssert(actualRequests[0]);
	});
}

void notifyConferenceEndedSendRequest(FlexiStats& flexiStats) {
	flexiStats.notifyConferenceEnded("iHVDMq6MxSKp60bT", getTestDate());
}
void notifyConferenceEndedCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "PATCH");
	BC_ASSERT_CPP_EQUAL(actualRequest->path, "/api/stats/conferences/iHVDMq6MxSKp60bT");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
	{
		"ended_at": "2017-07-21T17:32:28Z"
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void notifyConferenceEndedTest() {
	flexiStatTestFunc(notifyConferenceEndedSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		notifyConferenceEndedCustomAssert(actualRequests[0]);
	});
}

void conferenceAddParticipantEventSendRequest(FlexiStats& flexiStats) {
	const ParticipantEvent participantEvent{ParticipantEventType::ADDED, getTestDate()};
	flexiStats.conferenceAddParticipantEvent("iHVDMq6MxSKp60bT", *SipUri("sip:user1@domain.org").get(),
	                                         participantEvent);
}
void conferenceAddParticipantEventCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(actualRequest->path,
	                    "/api/stats/conferences/iHVDMq6MxSKp60bT/participants/user1@domain.org/events");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
	{
		"type": "added",
		"at": "2017-07-21T17:32:28Z"
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void conferenceAddParticipantEventTest() {
	flexiStatTestFunc(conferenceAddParticipantEventSendRequest, [](const vector<shared_ptr<Request>>& actualRequests) {
		conferenceAddParticipantEventCustomAssert(actualRequests[0]);
	});
}

void conferenceAddParticipantDeviceEventSendRequest(FlexiStats& flexiStats) {
	const ParticipantDeviceEvent participantDeviceEvent{ParticipantDeviceEventType::INVITED, getTestDate()};
	flexiStats.conferenceAddParticipantDeviceEvent("iHVDMq6MxSKp60bT", *SipUri("sip:user1@domain.org").get(),
	                                               "device_id", participantDeviceEvent);
}
void conferenceAddParticipantDeviceEventCustomAssert(const shared_ptr<Request>& actualRequest) {
	BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
	BC_ASSERT_CPP_EQUAL(
	    actualRequest->path,
	    "/api/stats/conferences/iHVDMq6MxSKp60bT/participants/user1@domain.org/devices/device_id/events");
	json actualJson;
	try {
		actualJson = json::parse(actualRequest->body);
	} catch (const json::exception&) {
		BC_FAIL("json::parse exception with received body");
	}
	const auto expectedJson = R"(
	{
		"type": "invited",
		"at": "2017-07-21T17:32:28Z"
	}
	)"_json;
	BC_ASSERT_CPP_EQUAL(actualJson, expectedJson);
}
void conferenceAddParticipantDeviceEventTest() {
	flexiStatTestFunc(conferenceAddParticipantDeviceEventSendRequest,
	                  [](const vector<shared_ptr<Request>>& actualRequests) {
		                  conferenceAddParticipantDeviceEventCustomAssert(actualRequests[0]);
	                  });
}

void conferenceMultiTest() {
	auto sendRequest = [](FlexiStats& flexiStats) {
		postConferenceFullSendRequest(flexiStats);
		conferenceAddParticipantEventSendRequest(flexiStats);
		conferenceAddParticipantDeviceEventSendRequest(flexiStats);
		notifyConferenceEndedSendRequest(flexiStats);
	};
	auto customAssert = [](const vector<shared_ptr<Request>>& actualRequests) {
		postConferenceFullCustomAssert(actualRequests[0]);
		conferenceAddParticipantEventCustomAssert(actualRequests[1]);
		conferenceAddParticipantDeviceEventCustomAssert(actualRequests[2]);
		notifyConferenceEndedCustomAssert(actualRequests[3]);
	};

	flexiStatTestFunc(sendRequest, customAssert, 4);
}

namespace {
TestSuite _("FlexiStatsClientUnitTests",
            {
                CLASSY_TEST(postMessageFullTest),
                CLASSY_TEST(postMessageMinimalTest),
                CLASSY_TEST(notifyMessageDeviceResponseTest),
                CLASSY_TEST(messageMultiTest),
                CLASSY_TEST(postCallFullTest),
                CLASSY_TEST(postCallMinimalTest),
                CLASSY_TEST(updateCallDeviceStateFullTest),
                CLASSY_TEST(updateCallDeviceStateRangOnlyTest),
                CLASSY_TEST(updateCallDeviceStateTerminatedOnlyTest),
                CLASSY_TEST(updateCallDeviceStateEmptyTest),
                CLASSY_TEST(updateCallStateTest),
                CLASSY_TEST(callMultiTest),
                CLASSY_TEST(postConferenceFullTest),
                CLASSY_TEST(postConferenceMinimalTest),
                CLASSY_TEST(notifyConferenceEndedTest),
                CLASSY_TEST(conferenceAddParticipantEventTest),
                CLASSY_TEST(conferenceAddParticipantDeviceEventTest),
                CLASSY_TEST(conferenceMultiTest),
            });
} // namespace

} // namespace tester::http_mock
} // namespace flexisip
