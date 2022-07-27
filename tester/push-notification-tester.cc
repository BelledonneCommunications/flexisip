/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <chrono>
#include <future>
#include <regex>
#include <thread>

#include "flexisip-config.h"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/timer.hh"

#include "pushnotification/apple/apple-client.hh"
#include "pushnotification/firebase/firebase-client.hh"
#include "tester.hh"
#include "utils/listening-socket.hh"
#include "utils/pns-mock.hh"

using namespace flexisip;
using namespace flexisip::pushnotification;
using namespace std;
using namespace std::chrono;

static su_root_t* root = nullptr;

static int beforeSuite() {
	root = su_root_create(nullptr);
	return 0;
}

static int afterSuite() {
	su_root_destroy(root);
	return 0;
}

static void startPushTest(Client& client,
                          const shared_ptr<Request>& request,
                          const string& reqBodyPattern,
                          int responseCode,
                          const string& responseBody,
                          Request::State expectedFinalState,
                          bool timeout = false) {
	std::promise<bool> barrier{};
	std::future<bool> barrier_future = barrier.get_future();
	PnsMock pnsMock;

	// Start of the push notification mock server
	auto isReqPatternMatched =
	    async(launch::async, [&pnsMock, responseCode, &responseBody, &reqBodyPattern, &barrier, timeout]() {
		    return pnsMock.exposeMock(responseCode, responseBody, reqBodyPattern, std::move(barrier), timeout);
	    });

	// Wait for the server to start
	barrier_future.wait();
	if (!barrier_future.get()) {
		BC_FAIL("Http2 mock server didn't start correctly");
	}

	if (timeout) client.setRequestTimeout(2s);
	// Send the push notification and wait until the request the request state is "Successful" or "Failed"
	client.sendPush(request);
	sofiasip::Timer timer{root, 50ms};
	auto beforePlus2 = system_clock::now() + 2s;
	timer.run([&request, &beforePlus2, &timeout]() {
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
			su_root_break(root);
		} else if (beforePlus2 >= system_clock::now() && !timeout) {
			SLOGW << "Test without timeout did not update request state";
			su_root_break(root);
		}
	});
	su_root_run(root);

	// NgHttp2 serveur normally don't stop until all connections are closed
	pnsMock.forceCloseServer();

	// Client (Firebase or Apple) onResponse/onError is called and response status is well managed
	BC_ASSERT_TRUE(request->getState() == expectedFinalState);

	// Mock server received a body matching reqBodyPattern, checked only if it's not a timeout case
	if (!timeout) {
		BC_ASSERT_TRUE(isReqPatternMatched.get() == true);
	}
}

static void startApplePushTest(PushType pType,
                               const std::shared_ptr<PushInfo>& pushInfo,
                               const string& reqBodyPattern,
                               int responseCode,
                               const string& responseBody,
                               Request::State expectedFinalState,
                               bool timeout = false) {
	AppleClient::APN_DEV_ADDRESS = "localhost";
	AppleClient::APN_PORT = "3000";
	AppleClient appleClient{*root, "", TESTER_DATA_DIR + string("/cert/apple.test.dev.pem"), "apple.test.dev.pem"};
	appleClient.enableInsecureTestMode();

	auto request = make_shared<AppleRequest>(pType, pushInfo);

	startPushTest(appleClient, move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState, timeout);
}

static void startFirebasePushTest(PushType pType,
                                  const std::shared_ptr<PushInfo>& pushInfo,
                                  const string& reqBodyPattern,
                                  int responseCode,
                                  const string& responseBody,
                                  Request::State expectedFinalState,
                                  bool timeout = false) {
	FirebaseClient::FIREBASE_ADDRESS = "localhost";
	FirebaseClient::FIREBASE_PORT = "3000";
	FirebaseClient firebaseClient{*root};
	firebaseClient.enableInsecureTestMode();

	auto request = make_shared<FirebaseRequest>(pType, pushInfo);

	startPushTest(firebaseClient, move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState,
	              timeout);
}

static void firebasePushTestOk(void) {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";

	string reqBodyPattern{R"json(\{
	"to":"",
	"time_to_live": 42,
	"priority":"high",
	"data":\{
		"uuid":"a-uid-42",
		"from-uri":"sip:kijou@sip.linphone.org",
		"display-name":"PushTestOk",
		"call-id":"",
		"sip-from":"PushTestOk",
		"loc-key":"",
		"loc-args":"PushTestOk",
		"send-time":"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
	\}
\})json"};

	startFirebasePushTest(PushType::Background, pushInfo, reqBodyPattern, 200, "ok", Request::State::Successful);
}

static void firebasePushTestKo(void) {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mAlertMsgId = "MessID";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCallId = "CallID";
	pushInfo->mTtl = (4 * 7 * 24h) + 1s; // intentionally set more than the allowed 4 weeks

	string reqBodyPattern{R"json(\{
	"to":"",
	"time_to_live": 2419200,
	"priority":"high",
	"data":\{
		"uuid":"",
		"from-uri":"sip:kijou@sip.linphone.org",
		"display-name":"",
		"call-id":"CallID",
		"sip-from":"sip:kijou@sip.linphone.org",
		"loc-key":"MessID",
		"loc-args":"sip:kijou@sip.linphone.org",
		"send-time":"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
	\}
\})json"};

	startFirebasePushTest(PushType::Background, pushInfo, reqBodyPattern, 500, "Internal error",
	                      Request::State::Failed);
}

static void firebasePushTestTimeout(void) {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTest";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";

	// Not checked during timeout test
	string reqBodyPattern{""};

	startFirebasePushTest(PushType::Background, pushInfo, reqBodyPattern, 200, "Ok", Request::State::Failed, true);
}

static void applePushTestOkPushkit(void) {
	auto dest = make_shared<RFC8599PushParams>("apns", "ABCD1234.org.linphone.phone.voip",
	                                           "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mAlertMsgId = "msgId2";
	pushInfo->mAlertSound = "Sonne";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCallId = "CallId2";
	pushInfo->mTtl = 42s;

	string reqBodyPattern{R"json(\{
	"aps": \{
		"sound": "",
		"loc-key": "msgId2",
		"loc-args": \["sip:kijou@sip.linphone.org"\],
		"call-id": "CallId2",
		"uuid": "",
		"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "",
	"pn_ttl": 42,
	"customPayload": \{\}
\})json"};

	startApplePushTest(PushType::VoIP, pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestOkBackground(void) {
	auto dest = make_shared<RFC8599PushParams>("apns", "ABCD1234.org.linphone.phone",
	                                           "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mCustomPayload = "{customData=\"CustomValue\"}";
	pushInfo->mAlertMsgId = "msgId";
	pushInfo->mFromName = "PushTestOkBackground";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCallId = "CallId";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";

	string reqBodyPattern{R"json(\{
	"aps": \{
		"badge": 0,
		"content-available": 1,
		"loc-key": "msgId",
		"loc-args": \["PushTestOkBackground"\],
		"call-id": "CallId",
		"uuid": "a-uid-42",
		"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}"
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "PushTestOkBackground",
	"pn_ttl": 42,
	"customPayload": \{customData="CustomValue"\}
\})json"};

	startApplePushTest(PushType::Background, pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestOkRemoteWithMutableContent(void) {
	auto dest = make_shared<RFC8599PushParams>("apns", "ABCD1234.org.linphone.phone",
	                                           "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mCustomPayload = "{customData=\"CustomValue\"}";
	pushInfo->mChatRoomAddr = "conference-0@sip.test.linphone.org";
	pushInfo->mAlertMsgId = "msgId";
	pushInfo->mAlertSound = "DuHast";
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mNoBadge = true;
	pushInfo->mCallId = "CallId";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";

	string reqBodyPattern{R"json(\{
	"aps": \{
		"alert": \{
			"loc-key": "msgId",
			"loc-args": \["PushTestOk"\]
		\},
		"sound": "DuHast",
		"mutable-content": 1,
		"badge": 0
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "PushTestOk",
	"call-id": "CallId",
	"pn_ttl": 42,
	"uuid": "a-uid-42",
	"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
	"chat-room-addr": "conference-0@sip.test.linphone.org",
	"customPayload": \{customData="CustomValue"\}
\})json"};

	startApplePushTest(PushType::Message, pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestKo(void) {
	auto dest =
	    make_shared<RFC8599PushParams>("apns", "", "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";

	const string reqBodyPattern{R"json(\{
	"aps": \{
		"alert": \{
			"loc-key": "",
			"loc-args": \["PushTestOk"\]
		\},
		"sound": "",
		"mutable-content": 1,
		"badge": 1
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "PushTestOk",
	"call-id": "",
	"pn_ttl": 0,
	"uuid": "",
	"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
	"chat-room-addr": "",
	"customPayload": \{\}
\})json"};

	startApplePushTest(PushType::Message, pushInfo, reqBodyPattern, 404, "Not found", Request::State::Failed);
}

static void applePushTestKoWrongType(void) {
	auto dest = make_shared<RFC8599PushParams>(
	    "apns",
	    "ABCD1234.org.linphone.phone", // PushType and appId don't match ("voip" not present)
	    "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->mAlertMsgId = "msgId2";
	pushInfo->mAlertSound = "Sonne";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCallId = "CallId2";
	pushInfo->mTtl = 42s;

	// The request will not be send to the server, we disable request check with timeout=true
	string reqBodyPattern{""};

	try {
		startApplePushTest(PushType::VoIP, pushInfo, reqBodyPattern, 0, "Doesn't even matter", Request::State::Failed,
		                   true);
	} catch (const invalid_argument& e) {
		// Instantiating a request of given type whereas no RFC8599 parameters are available for this type is
		// now a fatal error and the higher-level code must protect against that. Then, we expect a invalid_argument
		// exception.
		return;
	}
	BC_FAIL("No exception has been raised.");
}

static void applePushTestTimeout(void) {
	auto dest =
	    make_shared<RFC8599PushParams>("apns", "", "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTest";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";

	// Not checked during timeout test
	string reqBodyPattern{""};

	startApplePushTest(PushType::Message, pushInfo, reqBodyPattern, 200, "Ok", Request::State::Failed, true);
}

static void applePushTestConnectErrorAndReconnect(void) {
	auto dest = make_shared<RFC8599PushParams>("apns", "ABCD1234.org.linphone.phone",
	                                           "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mCustomPayload = "{customData=\"CustomValue\"}";
	pushInfo->mAlertMsgId = "msgId";
	pushInfo->mAlertSound = "DuHast";
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCallId = "CallId";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";

	const string reqBodyPattern{R"json(\{
	"aps": \{
		"alert": \{
			"loc-key": "msgId",
			"loc-args": \["PushTestOk"\]
		\},
		"sound": "DuHast",
		"mutable-content": 1,
		"badge": 1
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "PushTestOk",
	"call-id": "CallId",
	"pn_ttl": 42,
	"uuid": "a-uid-42",
	"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
	"chat-room-addr": "",
	"customPayload": \{customData="CustomValue"\}
\})json"};

	// We first send a request with mock off, leading to TLS connection error.
	AppleClient::APN_DEV_ADDRESS = "localhost";
	AppleClient::APN_PORT = "3000";
	AppleClient appleClient{*root, "", TESTER_DATA_DIR + string("/cert/apple.test.dev.pem"), "apple.test.dev.pem"};
	appleClient.enableInsecureTestMode();

	auto request = make_shared<AppleRequest>(PushType::Message, pushInfo);

	appleClient.sendPush(request);

	auto beforePlus1 = system_clock::now() + 1s;
	while (beforePlus1 >= system_clock::now()) {
		su_root_step(root, 100);
	}

	BC_ASSERT_TRUE(request->getState() == Request::State::Failed);

	// And then using the same AppleClient (so the same Http2Client) we send a second request with mock on this time and
	// check everything goes fine.
	startPushTest(appleClient, move(request), reqBodyPattern, 200, "Ok", Request::State::Successful, false);
}

static void tlsTimeoutTest(void) {
	FirebaseClient::FIREBASE_ADDRESS = "localhost";
	FirebaseClient::FIREBASE_PORT = "3000";
	FirebaseClient firebaseClient{*root};
	firebaseClient.enableInsecureTestMode();
	firebaseClient.getHttp2Client()->getConnection()->setTimeout(500ms);

	// Minimal request creation, values don't matter for this test
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);

	constexpr auto pType = PushType::Background;
	auto request = make_shared<FirebaseRequest>(pType, pushInfo);
	auto request2 = make_shared<FirebaseRequest>(pType, pushInfo);
	auto request3 = make_shared<FirebaseRequest>(pType, pushInfo);
	auto request4 = make_shared<FirebaseRequest>(pType, pushInfo);

	std::promise<void> barrier{};
	// Start listening on port 3000 with no response to simulate tls timeout
	auto isReqPatternMatched = async(launch::async, [&barrier]() { ListeningSocket::listenUntil(barrier); });

	// Send the push notifications and wait until the request state is "Successful" or "Failed"
	firebaseClient.sendPush(request);
	firebaseClient.sendPush(request2);
	firebaseClient.sendPush(request3);
	firebaseClient.sendPush(request4);
	sofiasip::Timer timer{root, 50ms};
	timer.run([request, &barrier]() {
		// All the requests should be rejected in the same loop, we can only watch one of them.
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
			su_root_break(root);
			barrier.set_value();
		}
	});
	su_root_run(root);

	// Client onError is called and response status is well managed, no crash occurred
	BC_ASSERT_TRUE(request->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request2->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request3->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request4->getState() == Request::State::Failed);
}

static test_t tests[] = {
    TEST_NO_TAG("Firebase push notification test OK", firebasePushTestOk),
    TEST_NO_TAG("Apple push notification test OK PushKit", applePushTestOkPushkit),
    TEST_NO_TAG("Apple push notification test OK Background", applePushTestOkBackground),
    TEST_NO_TAG("Apple push notification test OK RemoteWithMutableContent", applePushTestOkRemoteWithMutableContent),
    TEST_NO_TAG("Firebase push notification test KO", firebasePushTestKo),
    TEST_NO_TAG("Apple push notification test KO", applePushTestKo),
    TEST_NO_TAG("Apple push notification test KO wrong type", applePushTestKoWrongType),
    TEST_NO_TAG("Apple push notification test with a first connection failed and a reconnection (fix)",
                applePushTestConnectErrorAndReconnect),
    TEST_NO_TAG("Tls timeout test", tlsTimeoutTest),
    TEST_NO_TAG("Firebase push notification test timeout", firebasePushTestTimeout),
    TEST_NO_TAG("Apple push notification test timeout", applePushTestTimeout)};

test_suite_t push_notification_suite = {
    "Push notification", beforeSuite, afterSuite, nullptr, nullptr, sizeof(tests) / sizeof(tests[0]), tests};
