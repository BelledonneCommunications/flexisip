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
#include "flexisip-tester-config.hh"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "flexisip/utils/sip-uri.hh"

#include "push-notification-tester.hh"
#include "pushnotification/apple/apple-client.hh"
#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/contact-expiration-notifier.hh"
#include "pushnotification/firebase-v1/firebase-v1-client.hh"
#include "pushnotification/firebase-v1/firebase-v1-request.hh"
#include "pushnotification/generic/generic-http2-client.hh"
#include "pushnotification/push-notification-exceptions.hh"
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

static shared_ptr<sofiasip::SuRoot> root = nullptr;

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
	AppleClient::APN_DEV_ADDRESS = "127.0.0.1";
	AppleClient::APN_PORT = "3000";
	AppleClient appleClient{*root, "", bcTesterRes("cert/apple.test.dev.pem"), "apple.test.dev"};
	appleClient.enableInsecureTestMode();

	auto request = make_shared<AppleRequest>(pType, pushInfo);

	pn_tester::startPushTest(root, appleClient, std::move(request), reqBodyPattern, responseCode, responseBody,
	                         expectedFinalState, timeout);
}

/**
 * Common method to run a test for the firebase v1 client
 */
static void startFirebaseV1PushTest(PushType pType,
                                    const std::filesystem::path& pythonScriptPath,
                                    const std::shared_ptr<PushInfo>& pushInfo,
                                    const string& reqBodyPattern,
                                    int responseCode,
                                    const string& responseBody,
                                    Request::State expectedFinalState,
                                    bool timeout = false) {

	FirebaseV1Client::FIREBASE_ADDRESS = "127.0.0.1";
	FirebaseV1Client::FIREBASE_PORT = "3000";
	FirebaseV1Client firebaseClient{
	    *root, make_shared<FirebaseV1AuthenticationManager>(
	               root, pythonScriptPath, FLEXISIP_TESTER_DATA_SRCDIR "/config/firebase_sample_service_account.json",
	               15s, 30s)};
	firebaseClient.enableInsecureTestMode();

	auto request = make_shared<FirebaseV1Request>(pType, pushInfo, "sample-project");

	pn_tester::startPushTest(root, firebaseClient, std::move(request), reqBodyPattern, responseCode, responseBody,
	                         expectedFinalState, timeout);
}

/**
 * Send a push with the generic pusher.
 * Assert that the body is as intended and that the request state is correctly updated.
 */
template <const pn_tester::ExpectedResult expectedResult>
static void genericPushTest() {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";
	pushInfo->mText = "A body";
	pushInfo->mCallId = "callID";

	GenericHttp2Client genericHttp2Client{
	    sofiasip::Url(
	        "https://127.0.0.1:3000/generic?type=$type&from-name=$from-name&from-uri=$from-uri&call-id=$call-id"),
	    Method::HttpPost, *root};

	pn_tester::startGenericPushTest<expectedResult>(root, PushType::Background, pushInfo, pushInfo->mText, 200, "ok",
	                                                genericHttp2Client);
}

static void firebaseV1PushTestOk() {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "device_id");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uuid-42";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCustomPayload = R"({"key": "value", "key": {"key": "value"}})";

	string reqBodyPattern{R"json(\{
	"message":\{
		"token": "device_id",
		"android":\{
			"priority": "high",
			"ttl": "42s",
			"data":\{
				"uuid":"a-uuid-42",
				"from-uri":"sip:kijou@sip.linphone.org",
				"display-name":"",
				"call-id":"",
				"sip-from":"sip:kijou@sip.linphone.org",
				"loc-key":"",
				"loc-args":"sip:kijou@sip.linphone.org",
				"send-time":"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
				"custom-payload":"\{\\"key\\": \\"value\\", \\"key\\": \{\\"key\\": \\"value\\"\}\}"
			\}
		\}
	\}
\})json"};

	startFirebaseV1PushTest(PushType::Background,
	                        FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py", pushInfo,
	                        reqBodyPattern, 200, "ok", Request::State::Successful);
}

static void firebaseV1PushTestKo() {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "device_id");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mTtl = (4 * 7 * 24h) + 1s; // intentionally set more than the allowed 4 weeks
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mCallId = "CallID";
	pushInfo->mAlertMsgId = "MsgID";

	string reqBodyPattern{R"json(\{
	"message":\{
		"token": "device_id",
		"android":\{
			"priority": "high",
			"ttl": "2419200s",
			"data":\{
				"uuid":"",
				"from-uri":"sip:kijou@sip.linphone.org",
				"display-name":"",
				"call-id":"CallID",
				"sip-from":"sip:kijou@sip.linphone.org",
				"loc-key":"MsgID",
				"loc-args":"sip:kijou@sip.linphone.org",
				"send-time":"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
				"custom-payload":"\{\}"
			\}
		\}
	\}
\})json"};

	startFirebaseV1PushTest(PushType::Background,
	                        FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py", pushInfo,
	                        reqBodyPattern, 500, "Internal error", Request::State::Failed);
}

static void firebaseV1PushTestTimeout() {
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "device_id");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTest";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";

	// Request body pattern not checked during timeout test
	startFirebaseV1PushTest(PushType::Background,
	                        FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py", pushInfo,
	                        "", 200, "Ok", Request::State::Failed, true);
}

static void applePushTestOkPushkit() {
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

static void applePushTestOkBackground() {
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

static void applePushTestOkRemoteWithMutableContent() {
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

static void applePushTestKo() {
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

static void applePushTestKoWrongType() {
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

	// The request will not be sent to the server, we disable request check with timeout=true

	try {
		startApplePushTest(PushType::VoIP, pushInfo, "", 0, "Doesn't even matter", Request::State::Failed, true);
	} catch (const pushnotification::PushNotificationException& exception) {
		// Instantiating a request of given type whereas no RFC8599 parameters are available for this type is
		// now a fatal error and the higher-level code must protect against that. Then, we expect a invalid_argument
		// exception.
		return;
	}
	BC_FAIL("No exception has been raised.");
}

static void applePushTestTimeout() {
	auto dest =
	    make_shared<RFC8599PushParams>("apns", "", "6464646464646464646464646464646464646464646464646464646464646464");

	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTest";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";

	// Request body pattern not checked during timeout test.
	startApplePushTest(PushType::Message, pushInfo, "", 200, "Ok", Request::State::Failed, true);
}

static void applePushTestConnectErrorAndReconnect() {
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
	AppleClient::APN_DEV_ADDRESS = "127.0.0.1";
	AppleClient::APN_PORT = "3000";
	AppleClient appleClient{*root, "", bcTesterRes("cert/apple.test.dev.pem"), "apple.test.dev"};
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
	pn_tester::startPushTest(root, appleClient, std::move(request), reqBodyPattern, 200, "Ok",
	                         Request::State::Successful, false);
}

static void tlsTimeoutTest() {
	FirebaseV1Client::FIREBASE_ADDRESS = "127.0.0.1";
	FirebaseV1Client::FIREBASE_PORT = "3000";
	FirebaseV1Client firebaseClient{
	    *root, make_shared<FirebaseV1AuthenticationManager>(
	               root, FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py",
	               FLEXISIP_TESTER_DATA_SRCDIR "/config/firebase_sample_service_account.json", 15s, 30s)};
	firebaseClient.enableInsecureTestMode();
	firebaseClient.getHttp2Client()->getConnection()->setTimeout(500ms);

	// Minimal request creation, values don't matter for this test
	auto dest = make_shared<RFC8599PushParams>("fcm", "", "");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);

	constexpr auto pType = PushType::Background;
	auto request = make_shared<FirebaseV1Request>(pType, pushInfo, "sample-project");
	auto request2 = make_shared<FirebaseV1Request>(pType, pushInfo, "sample-project");
	auto request3 = make_shared<FirebaseV1Request>(pType, pushInfo, "sample-project");
	auto request4 = make_shared<FirebaseV1Request>(pType, pushInfo, "sample-project");

	std::promise<void> barrier{};
	// Start listening on port 3000 with no response to simulate tls timeout
	auto isReqPatternMatched = async(launch::async, [&barrier]() { ListeningSocket::listenUntil(barrier); });

	// Send the push notifications and wait until the request state is "Successful" or "Failed"
	firebaseClient.sendPush(request);
	firebaseClient.sendPush(request2);
	firebaseClient.sendPush(request3);
	firebaseClient.sendPush(request4);
	sofiasip::Timer timer{root, 50ms};
	timer.setForEver([request, &barrier]() {
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

	explicit operator SipUri() const {
		return SipUri(mStream.str());
	}
};

class TestNotifyExpiringContact : public RegistrarDbTest<DbImplementation::Internal> {
public:
	TestNotifyExpiringContact() {
		FirebaseV1Client::FIREBASE_ADDRESS = "127.0.0.1";
		FirebaseV1Client::FIREBASE_PORT = suitePort;
	}

protected:
	void testExec() noexcept override {
		auto passed = true;
		auto& regDb = mAgent->getRegistrarDb();
		auto service = std::make_shared<pushnotification::Service>(mRoot, 0xdead);
		// SIP only counts contact expiration in seconds, and 1s is apparently not enough to receive everything
		// as the notifier initialization and the registration of the contacts can be made over 2 different seconds
		// (creation of the notifier at .999 can create a lot of different scenarios).
		// Change threshold boundary with care, increasing the maximum will probably need an interval increase.
		const auto interval = 6s;
		const auto threshold = [] {
			auto engine = tester::random::engine();
			return std::uniform_real_distribution<float>(1. / 100, 50. / 100)(engine);
		}();
		auto minExpiration = interval + 2s;
		// Any contact expiring later than that cannot be sure to be returned because of seconds rounding
		auto maxExpiration = chrono::seconds(long((interval.count() - 1) / threshold) - 1);

		auto thresholdPostInterval = chrono::seconds(long(ceilf((interval.count() + 2) / threshold)));
		ContactExpirationNotifier notifier(interval, threshold, mRoot, service, regDb);

		auto appId = "fakeAppId";
		service->addFirebaseV1Client(
		    appId, FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py",
		    FLEXISIP_TESTER_DATA_SRCDIR "/config/firebase_sample_service_account.json", 15s, 30s);
		ContactInserter inserter{regDb};
		inserter.setExpire(maxExpiration)
		    .setAor(Contact("sip:expected2@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(minExpiration + (maxExpiration - minExpiration) / 2)
		    .setAor(Contact("sip:expected1@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(thresholdPostInterval)
		    .setAor(Contact("sip:unexpected@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(minExpiration)
		    .setAor(Contact("sip:expected3@example.org").withFirebasePushParams(appId))
		    .insert();
		inserter.setExpire(interval - 1s)
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

	sofiasip::Timer checkProgress(root, 50ms);
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
	auto client = Http2Client::make(root, "127.0.0.1", suitePort);
	auto request = [] {
		HttpHeaders headers{};
		headers.add(":method", "POST");
		headers.add(":scheme", "https");
		headers.add(":path", "/fcm/send");
		headers.add(":authority", string("127.0.0.1:") + suitePort);
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

TestSuite _("PushNotification",
            {
                TEST_NO_TAG("TestNotifyExpiringContact", run<TestNotifyExpiringContact>),
                TEST_NO_TAG_AUTO_NAMED(test_http2client__requests_that_can_not_be_sent_are_queued_and_sent_later),
                TEST_NO_TAG("FirebaseV1 push notification test OK", firebaseV1PushTestOk),
                TEST_NO_TAG("Apple push notification test OK PushKit", applePushTestOkPushkit),
                TEST_NO_TAG("Apple push notification test OK Background", applePushTestOkBackground),
                TEST_NO_TAG("Apple push notification test OK RemoteWithMutableContent",
                            applePushTestOkRemoteWithMutableContent),
                TEST_NO_TAG("FirebaseV1 push notification test KO", firebaseV1PushTestKo),
                TEST_NO_TAG("Apple push notification test KO", applePushTestKo),
                TEST_NO_TAG("Apple push notification test KO wrong type", applePushTestKoWrongType),
                TEST_NO_TAG("Apple push notification test with a first connection failed and a reconnection (fix)",
                            applePushTestConnectErrorAndReconnect),
                TEST_NO_TAG("Tls timeout test", tlsTimeoutTest),
                TEST_NO_TAG("FirebaseV1 push notification test timeout", firebaseV1PushTestTimeout),
                TEST_NO_TAG("Apple push notification test timeout", applePushTestTimeout),
                CLASSY_TEST(genericPushTest<pn_tester::Success>),
                CLASSY_TEST(genericPushTest<pn_tester::Timeout>),
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
