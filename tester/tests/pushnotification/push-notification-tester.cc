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

#include <chrono>
#include <cmath>
#include <future>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <thread>

#include "bctoolbox/tester.h"

#include "flexisip-config.h"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "flexisip/utils/sip-uri.hh"

#include "pushnotification/apple/apple-client.hh"
#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/contact-expiration-notifier.hh"
#include "pushnotification/firebase/firebase-client.hh"
#include "pushnotification/firebase/firebase-request.hh"
#include "pushnotification/generic/generic-http2-client.hh"
#include "tester.hh"
#include "utils/listening-socket.hh"
#include "utils/pns-mock.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::pushnotification;
using namespace flexisip::tester;
using namespace std;
using namespace std::chrono;

namespace pn = flexisip::pushnotification;
namespace server = nghttp2::asio_http2::server;

static std::unique_ptr<sofiasip::SuRoot> root = nullptr;

/**
 * Common method to run a push test
 */
static void startPushTest(Client& client,
                          const shared_ptr<Request>& request,
                          const string& reqBodyPattern,
                          int responseCode,
                          const string& responseBody,
                          Request::State expectedFinalState,
                          bool timeout) {
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
	// Send the push notification and wait until the request state is "Successful" or "Failed"
	client.sendPush(request);
	sofiasip::Timer timer{root->getCPtr(), 50ms};
	auto beforePlus2 = system_clock::now() + 2s;
	timer.run([&request, &beforePlus2, &timeout]() {
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
			su_root_break(root->getCPtr());
		} else if (beforePlus2 < system_clock::now() && !timeout) {
			SLOGW << "Test without timeout did not update request state";
			su_root_break(root->getCPtr());
		}
	});
	su_root_run(root->getCPtr());

	// NgHttp2 serveur normally don't stop until all connections are closed
	pnsMock.forceCloseServer();

	// Client (Firebase or Apple) onResponse/onError is called and response status is well managed
	BC_ASSERT_TRUE(request->getState() == expectedFinalState);

	// Mock server received a body matching reqBodyPattern, checked only if it's not a timeout case
	if (!timeout) {
		BC_ASSERT_TRUE(isReqPatternMatched.get() == true);
	}
}

/**
 * Common method to run a test for the apple client
 */
static void startApplePushTest(PushType pType,
                               const std::shared_ptr<PushInfo>& pushInfo,
                               const string& reqBodyPattern,
                               int responseCode,
                               const string& responseBody,
                               Request::State expectedFinalState,
                               bool timeout = false) {
	AppleClient::APN_DEV_ADDRESS = "localhost";
	AppleClient::APN_PORT = "3000";
	AppleClient appleClient{*root, "", bcTesterRes("cert/apple.test.dev.pem"), "apple.test.dev.pem"};
	appleClient.enableInsecureTestMode();

	auto request = make_shared<AppleRequest>(pType, pushInfo);

	startPushTest(appleClient, std::move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState,
	              timeout);
}

/**
 * Common method to run a test for the firebase client
 */
static void startFirebasePushTest(PushType pType,
                                  const std::shared_ptr<PushInfo>& pushInfo,
                                  const string& reqBodyPattern,
                                  int responseCode,
                                  const string& responseBody,
                                  Request::State expectedFinalState,
                                  bool timeout = false) {
	FirebaseClient::FIREBASE_ADDRESS = "localhost";
	FirebaseClient::FIREBASE_PORT = "3000";
	FirebaseClient firebaseClient{*root, ""};
	firebaseClient.enableInsecureTestMode();

	auto request = make_shared<FirebaseRequest>(pType, pushInfo);

	startPushTest(firebaseClient, std::move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState,
	              timeout);
}

/**
 * Common method to run a test for the generic pusher
 */
static void startGenericPushTest(PushType pType,
                                 const std::shared_ptr<PushInfo>& pushInfo,
                                 const string& reqBodyPattern,
                                 int responseCode,
                                 const string& responseBody,
                                 Request::State expectedFinalState,
                                 bool timeout = false) {

	GenericHttp2Client genericClient{
	    sofiasip::Url(
	        "https://localhost:3000/generic?type=$type&from-name=$from-name&from-uri=$from-uri&call-id=$call-id"),
	    Method::HttpPost, *root};
	genericClient.enableInsecureTestMode();

	auto request = genericClient.makeRequest(pType, pushInfo);

	startPushTest(genericClient, std::move(request), reqBodyPattern, responseCode, responseBody, expectedFinalState,
	              timeout);
}

/**
 * Send a push with the generic pusher.
 * Assert that the body is as intended and that the request state is correctly updated.
 */
static void genericPushTestOk(void) {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";
	pushInfo->mText = "A body";
	pushInfo->mCallId = "callID";

	startGenericPushTest(PushType::Background, pushInfo, pushInfo->mText, 200, "ok", Request::State::Successful);
}

/**
 * Send a push with the generic pusher but the mock timeout.
 * Assert that the request state is correctly updated.
 */
static void genericPushTestTimeout(void) {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";
	pushInfo->mText = "A body";
	pushInfo->mCallId = "callID";

	startGenericPushTest(PushType::Background, pushInfo, pushInfo->mText, 200, "ok", Request::State::Failed, true);
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
		"custom-payload":\{\}
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
		"custom-payload":\{\}
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
	AppleClient appleClient{*root, "", bcTesterRes("cert/apple.test.dev.pem"), "apple.test.dev.pem"};
	appleClient.enableInsecureTestMode();

	auto request = make_shared<AppleRequest>(PushType::Message, pushInfo);

	appleClient.sendPush(request);

	auto beforePlus1 = system_clock::now() + 1s;
	while (beforePlus1 >= system_clock::now()) {
		su_root_step(root->getCPtr(), 100);
	}

	BC_ASSERT_TRUE(request->getState() == Request::State::Failed);

	// And then using the same AppleClient (so the same Http2Client) we send a second request with mock on this time and
	// check everything goes fine.
	startPushTest(appleClient, std::move(request), reqBodyPattern, 200, "Ok", Request::State::Successful, false);
}

static void tlsTimeoutTest(void) {
	FirebaseClient::FIREBASE_ADDRESS = "localhost";
	FirebaseClient::FIREBASE_PORT = "3000";
	FirebaseClient firebaseClient{*root, ""};
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
	sofiasip::Timer timer{root->getCPtr(), 50ms};
	timer.run([request, &barrier]() {
		// All the requests should be rejected in the same loop, we can only watch one of them.
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
			su_root_break(root->getCPtr());
			barrier.set_value();
		}
	});
	su_root_run(root->getCPtr());

	// Client onError is called and response status is well managed, no crash occurred
	BC_ASSERT_TRUE(request->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request2->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request3->getState() == Request::State::Failed);
	BC_ASSERT_TRUE(request4->getState() == Request::State::Failed);
}

namespace {

constexpr auto suitePort = "57005";

class Contact {
	ostringstream mStream;

public:
	template <typename T>
	Contact(T&& name) {
		mStream << name;
	}

	template <typename T>
	Contact& withFirebasePushParams(T&& appId) {
		mStream << ";pn-provider=fcm;pn-prid=placeholder-prid;pn-param=" << appId;
		return *this;
	}

	Contact& withAppleVoipOnlyPushParams() {
		mStream << ";pn-provider=apns;pn-prid=placeholder-prid;pn-param=placeholder.voip";
		return *this;
	}

	operator SipUri() const {
		return SipUri(mStream.str());
	}
};

class TestNotifyExpiringContact : public RegistrarDbTest<DbImplementation::Internal> {
public:
	TestNotifyExpiringContact() {
		FirebaseClient::FIREBASE_ADDRESS = "localhost";
		FirebaseClient::FIREBASE_PORT = suitePort;
	}

protected:
	void testExec() noexcept override {
		auto passed = true;
		auto& regDb = *RegistrarDb::get();
		auto service = std::make_shared<pushnotification::Service>(*mRoot, 0xdead);
		// SIP only counts contact expiration in seconds, and 1s is apparently not enough to receive everything
		const auto interval = 2s;
		const auto threshold = [] {
			auto engine = tester::randomEngine();
			return std::uniform_real_distribution<float>(1. / 100, 50. / 100)(engine);
		}();
		auto minExpiration = interval + 1s;
		// Any contact expiring later than that should not be returned
		auto maxExpiration = chrono::seconds(long(ceilf(interval.count() / threshold)) - 1);
		ContactExpirationNotifier notifier(interval, threshold, mRoot, service, regDb);

		auto appId = "fakeAppId";
		service->addFirebaseClient(appId);
		ContactInserter inserter{regDb};
		inserter.setExpire(maxExpiration)
		    .setAor(Contact("sip:expected2@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(minExpiration + (maxExpiration - minExpiration) / 2)
		    .setAor(Contact("sip:expected1@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(maxExpiration + 1s)
		    .setAor(Contact("sip:unexpected@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(minExpiration)
		    .setAor(Contact("sip:expected3@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(minExpiration - 1s)
		    .setAor(Contact("sip:expired@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter
		    // within range...
		    .setExpire(maxExpiration)
		    // ...but nothing to do
		    .setAor("sip:unnotifiable@example.org")
		    .insert()
		    // ...but cannot be woken up via Background type notifications
		    .setAor(Contact("sip:unwakeable@example.org").withAppleVoipOnlyPushParams())
		    .insert();
		auto expectedUris = unordered_set<string>{"expected1", "expected2", "expected3"};

		pn::PnsMock pnServer;
		pnServer.onPushRequest(
		    [&sofiaLoop = *mRoot, &expectedUris, &passed](const server::request& req, const server::response& res) {
			    res.write_head(200);
			    res.end("ok");

			    req.on_data([&sofiaLoop, &expectedUris, &passed](const uint8_t* data, std::size_t len) {
				    if (0 < len) {
					    auto body = string(reinterpret_cast<const char*>(data), len);
					    static const auto extractFromUri =
					        regex(R"r("from-uri":"sip:(.*)@example.org)r", regex::ECMAScript);
					    std::smatch matches;
					    regex_search(body, matches, extractFromUri);
					    // Fail when receiving push for unexpected contact
					    string contactString(matches[1]);
					    auto found = expectedUris.erase(contactString);
					    passed &= bc_assert(__FILE__, __LINE__, found == 1,
					                        ("unexpected contact returned: " + contactString).c_str());
					    if (expectedUris.empty()) {
						    sofiaLoop.quit(); // Test passed
					    }
				    }
			    });
		    });
		pnServer.serveAsync(suitePort);

		sofiasip::Timer timeout(mRoot, interval * 2 - 100ms); // Right before the notifier would run again
		timeout.set([&sofiaLoop = *mRoot, &inserter, &expectedUris, &passed] {
			passed = false;
			BC_ASSERT_TRUE(inserter.finished());
			ostringstream msg{};
			msg << "Test timed out while still expecting: ";
			for (const auto& remaining : expectedUris) {
				msg << remaining << " ";
			}
			bc_assert(__FILE__, __LINE__, false, msg.str().c_str());
			sofiaLoop.quit();
		});

		mRoot->run();     // Notifier executes after `interval`, if something went wrong the timeout will trigger
		mRoot->step(0ms); // Stepping one more time to let callbacks be cleaned up properly
		bc_assert(__FILE__, __LINE__, passed, ("Test failed with threshold value: " + to_string(threshold)).c_str());
	}
};

// Because this test relies heavily on callbacks, it's easier to read it from the bottom up
void test_http2client__requests_that_can_not_be_sent_are_queued_and_sent_later() {
	sofiasip::SuRoot root{};
	uint32_t sentCount = 0;
	uint32_t respondedCount = 0;
	atomic<uint32_t> receivedCount(0);

	sofiasip::Timer checkProgress(root.getCPtr(), 50ms);
	uint32_t previous = 0;
	auto progressChecker = [&previous, &respondedCount, &root]() mutable {
		// if something changed, we're good
		if (previous != respondedCount) {
			previous = respondedCount;
			return;
		}

		BC_FAIL("Test seems stuck. Aborting");
		root.quit();
	};

	auto onError = [&root]([[maybe_unused]] const auto& req) {
		BC_FAIL("Request error");
		root.quit();
	};
	auto onResponse = [&respondedCount, &sentCount, &root]([[maybe_unused]] const auto& req,
	                                                       [[maybe_unused]] const auto& res) {
		respondedCount++;
		if (respondedCount == sentCount) {
			root.quit();
		}
	};

	pn::PnsMock pnServer{};
	std::mutex serverProcessing{};
	pnServer.onPushRequest([&receivedCount, &serverProcessing]([[maybe_unused]] const auto& req, const auto& res) {
		receivedCount++;
		serverProcessing.lock();
		serverProcessing.unlock();
		res.write_head(200);
		res.end("ok");
	});
	pnServer.serveAsync(suitePort);

	// Send a first request to establish the connection
	auto client = Http2Client::make(root, "localhost", suitePort);
	auto request = [] {
		HttpHeaders headers{};
		headers.add(":method", "POST");
		headers.add(":scheme", "https");
		headers.add(":path", "/fcm/send");
		headers.add(":authority", string("localhost:") + suitePort);
		return make_shared<Http2Client::HttpRequest>(headers, std::vector<char>(0x100, '!'));
	}();
	client->send(
	    request,
	    [&receivedCount, &serverProcessing, &client, &request, &onResponse, &onError, &sentCount, &checkProgress,
	     &progressChecker]([[maybe_unused]] const auto& req, [[maybe_unused]] const auto& res) {
		    // Connection established
		    BC_ASSERT_EQUAL(receivedCount, 1, uint32_t, "%i");
		    receivedCount = 0;
		    serverProcessing.lock();
		    while (client->getOutboundQueueSize() < 2) {
			    client->send(request, onResponse, onError);
			    sentCount++;
		    }
		    // We've hit a buffer limit (probably the max number of concurrent streams)
		    // If we send twice as much, then we should reach that limit a second time after we've unlocked processing,
		    // and that should be enough for this test
		    for (size_t _ = 0; _ < sentCount; _++) {
			    client->send(request, onResponse, onError);
		    }
		    sentCount *= 2;
		    serverProcessing.unlock();
		    checkProgress.setForEver(progressChecker); // Assert requests are being handled
	    },
	    onError);

	root.run();

	SLOGD << __FUNCTION__ << " - Number of requests sent: " << sentCount;
	BC_ASSERT_EQUAL(receivedCount, sentCount, uint32_t, "%i");
	BC_ASSERT_EQUAL(respondedCount, sentCount, uint32_t, "%i");
}

TestSuite _("Push notification",
            {
                TEST_NO_TAG("TestNotifyExpiringContact", run<TestNotifyExpiringContact>),
                TEST_NO_TAG_AUTO_NAMED(test_http2client__requests_that_can_not_be_sent_are_queued_and_sent_later),
                TEST_NO_TAG("Firebase push notification test OK", firebasePushTestOk),
                TEST_NO_TAG("Apple push notification test OK PushKit", applePushTestOkPushkit),
                TEST_NO_TAG("Apple push notification test OK Background", applePushTestOkBackground),
                TEST_NO_TAG("Apple push notification test OK RemoteWithMutableContent",
                            applePushTestOkRemoteWithMutableContent),
                TEST_NO_TAG("Firebase push notification test KO", firebasePushTestKo),
                TEST_NO_TAG("Apple push notification test KO", applePushTestKo),
                TEST_NO_TAG("Apple push notification test KO wrong type", applePushTestKoWrongType),
                TEST_NO_TAG("Apple push notification test with a first connection failed and a reconnection (fix)",
                            applePushTestConnectErrorAndReconnect),
                TEST_NO_TAG("Tls timeout test", tlsTimeoutTest),
                TEST_NO_TAG("Firebase push notification test timeout", firebasePushTestTimeout),
                TEST_NO_TAG("Apple push notification test timeout", applePushTestTimeout),
                TEST_NO_TAG("Generic test ok", genericPushTestOk),
                TEST_NO_TAG("Generic test ko, timeout", genericPushTestTimeout),
            },
            Hooks()
                .beforeSuite([] {
	                root = make_unique<sofiasip::SuRoot>();
	                return 0;
                })
                .afterSuite([] {
	                root.reset();
	                return 0;
                }));

} // namespace
