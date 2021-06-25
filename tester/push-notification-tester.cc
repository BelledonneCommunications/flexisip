/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <flexisip/utils/timer.hh>

#include "flexisip-config.h"
#include "flexisip/logmanager.hh"

#include "pushnotification/apple/apple-client.hh"
#include "pushnotification/firebase/firebase-client.hh"
#include "tester.hh"
#include "utils/listening-socket.hh"
#include "utils/pns-mock.hh"

using namespace flexisip;
using namespace flexisip::pushnotification;
using namespace std;

static su_root_t* root = nullptr;

static int beforeSuite() {
	root = su_root_create(nullptr);
	return 0;
}

static int afterSuite() {
	su_root_destroy(root);
	return 0;
}

static void startPushTest(Client& client, const shared_ptr<Request>& request, const string& reqBodyPattern,
                          int responseCode, const string& responseBody, const Request::State& expectedFinalState,
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

	// Send the push notification and wait until the request the request state is "Successful" or "Failed"
	client.sendPush(request);
	sofiasip::Timer timer{root, 500};
	timer.run([request]() {
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
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

static void startApplePushTest(const PushInfo& pushInfo, const string& reqBodyPattern, int responseCode,
                               const string& responseBody, const Request::State& expectedFinalState,
                               bool timeout = false) {
	AppleClient::APN_DEV_ADDRESS = "localhost";
	AppleClient::APN_PORT = "3000";
	AppleClient appleClient{*root, "", TESTER_DATA_DIR + string("/cert/apple.test.dev.pem"), "apple.test.dev.pem"};
	appleClient.enableInsecureTestMode();

	auto request = make_shared<AppleRequest>(pushInfo);

	startPushTest(appleClient, move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState, timeout);
}

static void startFirebasePushTest(const PushInfo& pushInfo, const string& reqBodyPattern, int responseCode,
                                  const string& responseBody, const Request::State& expectedFinalState,
                                  bool timeout = false) {
	FirebaseClient::FIREBASE_ADDRESS = "localhost";
	FirebaseClient::FIREBASE_PORT = "3000";
	FirebaseClient firebaseClient{*root};
	firebaseClient.enableInsecureTestMode();

	auto request = make_shared<FirebaseRequest>(pushInfo);

	startPushTest(firebaseClient, move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState,
	              timeout);
}

static void firebasePushTestOk(void) {
	PushInfo pushInfo{};
	pushInfo.mFromName = "PushTestOk";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mTtl = 42;
	pushInfo.mUid = "a-uid-42";

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

	startFirebasePushTest(pushInfo, reqBodyPattern, 200, "ok", Request::State::Successful);
}

static void firebasePushTestKo(void) {
	PushInfo pushInfo{};
	pushInfo.mAlertMsgId = "MessID";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mCallId = "CallID";
	pushInfo.mTtl = (4 * 7 * 24 * 3600) + 1; // 2419201, more than max 2419200 allowed

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

	startFirebasePushTest(pushInfo, reqBodyPattern, 500, "Internal error", Request::State::Failed);
}

static void firebasePushTestTimeout(void) {
	PushInfo pushInfo{};
	pushInfo.mFromName = "PushTest";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";

	// Not checked during timeout test
	string reqBodyPattern{""};

	startFirebasePushTest(pushInfo, reqBodyPattern, 200, "Ok", Request::State::Failed, true);
}

static void applePushTestOkRemoteBasic(void) {
	PushInfo pushInfo{};
	pushInfo.mApplePushType = ApplePushType::RemoteBasic;
	pushInfo.mCustomPayload = "{customData=\"CustomValue\"}";
	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mAlertMsgId = "msgId";
	pushInfo.mAlertSound = "DuHast";
	pushInfo.mFromName = "PushTestOk";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mCallId = "CallId";
	pushInfo.mAppId = "org.linphone.phone.prod";
	pushInfo.mTtl = 42;
	pushInfo.mUid = "a-uid-42";

	// Not checked during timeout test
	string reqBodyPattern{R"json(\{
	"aps": \{
		"alert": \{
			"loc-key": "msgId",
			"loc-args": \["PushTestOk"\]
		\},
		"sound": "DuHast",
		"badge": 1
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "PushTestOk",
	"call-id": "CallId",
	"pn_ttl": 42,
	"uuid": "a-uid-42",
	"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
	"customPayload": \{customData="CustomValue"\}
\})json"};

	startApplePushTest(pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestOkPushkit(void) {
	PushInfo pushInfo{};
	pushInfo.mApplePushType = ApplePushType::Pushkit;
	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mAlertMsgId = "msgId2";
	pushInfo.mAlertSound = "Sonne";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mCallId = "CallId2";
	pushInfo.mAppId = "org.linphone.phone.voip.prod";
	pushInfo.mTtl = 42;

	// Not checked during timeout test
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

	startApplePushTest(pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestOkBackground(void) {
	PushInfo pushInfo{};
	pushInfo.mApplePushType = ApplePushType::Background;
	pushInfo.mCustomPayload = "{customData=\"CustomValue\"}";
	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mAlertMsgId = "msgId";
	pushInfo.mFromName = "PushTestOkBackground";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mCallId = "CallId";
	pushInfo.mAppId = "org.linphone.phone.prod";
	pushInfo.mTtl = 42;
	pushInfo.mUid = "a-uid-42";

	// Not checked during timeout test
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

	startApplePushTest(pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestOkRemoteWithMutableContent(void) {
	PushInfo pushInfo{};
	pushInfo.mApplePushType = ApplePushType::RemoteWithMutableContent;
	pushInfo.mCustomPayload = "{customData=\"CustomValue\"}";
	pushInfo.mChatRoomAddr = "conference-0@sip.test.linphone.org";
	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mAlertMsgId = "msgId";
	pushInfo.mAlertSound = "DuHast";
	pushInfo.mFromName = "PushTestOk";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mNoBadge = true;
	pushInfo.mCallId = "CallId";
	pushInfo.mAppId = "org.linphone.phone.prod";
	pushInfo.mTtl = 42;
	pushInfo.mUid = "a-uid-42";

	// Not checked during timeout test
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

	startApplePushTest(pushInfo, reqBodyPattern, 200, "Ok", Request::State::Successful);
}

static void applePushTestKo(void) {
	PushInfo pushInfo{};
	pushInfo.mApplePushType = ApplePushType::RemoteBasic;
	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mFromName = "PushTestOk";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";

	// Not checked during timeout test
	string reqBodyPattern{R"json(\{
	"aps": \{
		"alert": \{
			"loc-key": "",
			"loc-args": \["PushTestOk"\]
		\},
		"sound": "",
		"badge": 1
	\},
	"from-uri": "sip:kijou@sip.linphone.org",
	"display-name": "PushTestOk",
	"call-id": "",
	"pn_ttl": 0,
	"uuid": "",
	"send-time": "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
	"customPayload": \{\}
\})json"};

	startApplePushTest(pushInfo, reqBodyPattern, 404, "Not found", Request::State::Failed);
}

static void applePushTestKoWrongType(void) {
	PushInfo pushInfo{};
	// PushType and appId don't match ("voip" not present)
	pushInfo.mApplePushType = ApplePushType::Pushkit;
	pushInfo.mAppId = "org.linphone.phone.prod";

	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mAlertMsgId = "msgId2";
	pushInfo.mAlertSound = "Sonne";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo.mCallId = "CallId2";
	pushInfo.mTtl = 42;

	// The request will not be send to the server, we disable request check with timeout=true
	string reqBodyPattern{""};
	startApplePushTest(pushInfo, reqBodyPattern, 0, "Doesn't even matter", Request::State::Failed, true);
}

static void applePushTestTimeout(void) {
	PushInfo pushInfo{};
	pushInfo.mApplePushType = ApplePushType::RemoteBasic;
	pushInfo.mDeviceToken = "6464646464646464646464646464646464646464646464646464646464646464";
	pushInfo.mFromName = "PushTest";
	pushInfo.mFromUri = "sip:kijou@sip.linphone.org";

	// Not checked during timeout test
	string reqBodyPattern{""};

	startApplePushTest(pushInfo, reqBodyPattern, 200, "Ok", Request::State::Failed, true);
}

static void tlsTimeoutTest(void) {
	FirebaseClient::FIREBASE_ADDRESS = "localhost";
	FirebaseClient::FIREBASE_PORT = "3000";
	FirebaseClient firebaseClient{*root};
	firebaseClient.enableInsecureTestMode();

	// Minimal request creation, values don't matter for this test
	PushInfo pushInfo{};
	auto request = make_shared<FirebaseRequest>(pushInfo);
	auto request2 = make_shared<FirebaseRequest>(pushInfo);
	auto request3 = make_shared<FirebaseRequest>(pushInfo);
	auto request4 = make_shared<FirebaseRequest>(pushInfo);

	std::promise<void> barrier{};
	// Start listening on port 3000 with no response to simulate tls timeout
	auto isReqPatternMatched = async(launch::async, [&barrier]() { ListeningSocket::listenUntil(barrier); });

	// Send the push notifications and wait until the request the request state is "Successful" or "Failed"
	firebaseClient.sendPush(request);
	firebaseClient.sendPush(request2);
	firebaseClient.sendPush(request3);
	firebaseClient.sendPush(request4);
	sofiasip::Timer timer{root, 500};
	timer.run([request, &barrier]() {
		// All the requests should be rejected in the same loop, we can only watch one of them.
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
			su_root_break(root);
			barrier.set_value();
		}
	});
	su_root_run(root);

	// Client onError is called and response status is well managed, no crash occured
	BC_ASSERT_TRUE(request->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request2->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request3->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request4->getState() == Request::State::Failed);
}

static test_t tests[] = {
    TEST_NO_TAG("Firebase push notification test OK", firebasePushTestOk),
    TEST_NO_TAG("Apple push notification test OK RemoteBasic", applePushTestOkRemoteBasic),
    TEST_NO_TAG("Apple push notification test OK PushKit", applePushTestOkPushkit),
    TEST_NO_TAG("Apple push notification test OK Background", applePushTestOkBackground),
    TEST_NO_TAG("Apple push notification test OK RemoteWithMutableContent", applePushTestOkRemoteWithMutableContent),
    TEST_NO_TAG("Firebase push notification test KO", firebasePushTestKo),
    TEST_NO_TAG("Apple push notification test KO", applePushTestKo),
    TEST_NO_TAG("Apple push notification test KO wrong type", applePushTestKoWrongType),
    TEST_NO_TAG("Tls timeout test", tlsTimeoutTest),
    TEST_NO_TAG("Firebase push notification test timeout", firebasePushTestTimeout),
    TEST_NO_TAG("Apple push notification test timeout", applePushTestTimeout)};

test_suite_t push_notification_suite = {
    "Push notification", beforeSuite, afterSuite, nullptr, nullptr, sizeof(tests) / sizeof(tests[0]), tests};
