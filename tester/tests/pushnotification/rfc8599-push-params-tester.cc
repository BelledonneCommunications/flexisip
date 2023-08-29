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

#include "flexisip/logmanager.hh"
#include "pushnotification/rfc8599-push-params.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {
using namespace pushnotification;

static void setFromLegacyParamsTest() {
	RFC8599PushParams appleProd{};
	appleProd.setFromLegacyParams("apple", "fr.bc-appId.prod", "pnTok");
	BC_HARD_ASSERT_CPP_EQUAL(appleProd.getProvider(), "apns");
	BC_HARD_ASSERT_CPP_EQUAL(appleProd.getParam(), "ABCD1234.fr.bc-appId");
	BC_HARD_ASSERT_CPP_EQUAL(appleProd.getPrid(), "pnTok");

	RFC8599PushParams appleDev{};
	appleDev.setFromLegacyParams("apple", "fr.bc-appId.test.dev", "pnTok.tok");
	BC_HARD_ASSERT_CPP_EQUAL(appleDev.getProvider(), "apns.dev");
	BC_HARD_ASSERT_CPP_EQUAL(appleDev.getParam(), "ABCD1234.fr.bc-appId.test");
	BC_HARD_ASSERT_CPP_EQUAL(appleDev.getPrid(), "pnTok.tok");

	RFC8599PushParams apple{};
	apple.setFromLegacyParams("apple", "fr.bc-appId.test", "pnTok.toktok");
	BC_HARD_ASSERT_CPP_EQUAL(apple.getProvider(), "apns");
	BC_HARD_ASSERT_CPP_EQUAL(apple.getParam(), "ABCD1234.fr.bc-appId.test");
	BC_HARD_ASSERT_CPP_EQUAL(apple.getPrid(), "pnTok.toktok");

	RFC8599PushParams firebase{};
	firebase.setFromLegacyParams("firebase", "fr.bc-appId.test", "pnTok.toktok");
	BC_HARD_ASSERT_CPP_EQUAL(firebase.getProvider(), "fcm");
	BC_HARD_ASSERT_CPP_EQUAL(firebase.getParam(), "fr.bc-appId.test");
	BC_HARD_ASSERT_CPP_EQUAL(firebase.getPrid(), "pnTok.toktok");

	RFC8599PushParams android{};
	android.setFromLegacyParams("android", "fr.bc-appId.test", "pnTok.toktok");
	BC_HARD_ASSERT_CPP_EQUAL(android.getProvider(), "fcm");
	BC_HARD_ASSERT_CPP_EQUAL(android.getParam(), "fr.bc-appId.test");
	BC_HARD_ASSERT_CPP_EQUAL(android.getPrid(), "pnTok.toktok");

	RFC8599PushParams google{};
	android.setFromLegacyParams("google", "fr.bc-appId.test", "pnTok.toktok");
	BC_HARD_ASSERT_CPP_EQUAL(android.getProvider(), "fcm");
	BC_HARD_ASSERT_CPP_EQUAL(android.getParam(), "fr.bc-appId.test");
	BC_HARD_ASSERT_CPP_EQUAL(android.getPrid(), "pnTok.toktok");

	RFC8599PushParams others{};
	others.setFromLegacyParams("anyOtherSource", "fr.bc-appId.test", "pnTok.toktok");
	BC_HARD_ASSERT_CPP_EQUAL(others.getProvider(), "anyOtherSource");
	BC_HARD_ASSERT_CPP_EQUAL(others.getParam(), "fr.bc-appId.test");
	BC_HARD_ASSERT_CPP_EQUAL(others.getPrid(), "pnTok.toktok");
};

namespace {

TestSuite _("RFC8599PushParams unit tests",
            {
                CLASSY_TEST(setFromLegacyParamsTest),
            });

}
} // namespace flexisip::tester
