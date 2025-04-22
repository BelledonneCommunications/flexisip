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
#include <string>

#include "bctoolbox/tester.h"

#include "push-notification-tester.hh"

#include "flexiapi/schemas/pushnotification/pushnotification.hh"
#include "pushnotification/flexiapi/flexiapi-request.hh"
#include "pushnotification/generic/generic-http2-client.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace flexisip::tester;
using namespace std;

namespace flexisip::pushnotification::pn_tester {

/**
 * Send a push with the generic pusher using the FlexiAPI	.
 * Assert that the body is as intended and that the request state is correctly updated.
 */
template <const ExpectedResult expectedResult>
void flexiApiPushTest() {
	static const auto root = make_shared<sofiasip::SuRoot>();

	auto dest = make_shared<RFC8599PushParams>("apns", "ABCD1234.org.linphone.phone.voip", "some-id");
	auto pushInfo = make_shared<PushInfo>();
	pushInfo->addDestination(dest);
	pushInfo->mFromName = "PushTestOk";
	pushInfo->mFromUri = "sip:kijou@sip.linphone.org";
	pushInfo->mTtl = 42s;
	pushInfo->mUid = "a-uid-42";
	pushInfo->mCallId = "callID";

	string reqBodyPattern{R"json(\{
	"pn_provider":"fcm|apns|apns.dev",
	"pn_param": "ABCD1234.org.linphone.phone.voip",
	"pn_prid": "some-id",
	"type": "background|call|message",
	"call_id": "callID"
\})json"};

	GenericHttp2Client genericHttp2Client{sofiasip::Url("https://127.0.0.1:3000/flexiapi/push_notification"),
	                                      "api-key",
	                                      FlexiApiBodyGenerationFunc,
	                                      *root,
	                                      nullptr,
	                                      nullptr};

	startGenericPushTest<expectedResult>(root, PushType::VoIP, pushInfo, reqBodyPattern, 200, "ok", genericHttp2Client);
}

TestSuite _{
    "PushNotification::Flexiapi",
    {
        CLASSY_TEST(flexiApiPushTest<Success>),
        CLASSY_TEST(flexiApiPushTest<Timeout>),
    },
};
} // namespace flexisip::pushnotification::pn_tester
