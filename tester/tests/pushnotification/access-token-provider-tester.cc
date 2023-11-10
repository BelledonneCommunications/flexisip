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

#include "flexisip-tester-config.hh"

#include "pushnotification/firebase-v1/firebase-v1-access-token-provider.hh"
#include "pushnotification/firebase-v1/firebase-v1-authentication-manager.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

#define PY_SCRIPT_ERROR FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_error.py"
#define PY_SCRIPT_SUCCESS_F FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success_fixed.py"
#define FIREBASE_SAMPLE_FILE FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/config/firebase_sample_service_account.json"

using namespace std;
using HttpRequest = flexisip::HttpMessage;

namespace flexisip::tester {
using namespace pushnotification;

namespace firebaseV1 {

void testInstantiateWrongPathToPythonScript() {
	BC_ASSERT_THROWN(make_unique<FirebaseV1AccessTokenProvider>("wrong/path/to/script.py", FIREBASE_SAMPLE_FILE),
	                 std::runtime_error);
}

void testGetTokenSuccess() {
	const auto provider = make_unique<FirebaseV1AccessTokenProvider>(PY_SCRIPT_SUCCESS_F, FIREBASE_SAMPLE_FILE);

	const auto token = provider->getToken();

	BC_ASSERT_TRUE(token != nullopt);
	BC_ASSERT_TRUE(token->lifetime == 42s);
	BC_ASSERT_CPP_EQUAL(token->content, "THIS_IS_AN_ACCESS_TOKEN");
}

void testGetTokenError() {
	const auto provider = make_unique<FirebaseV1AccessTokenProvider>(PY_SCRIPT_ERROR, FIREBASE_SAMPLE_FILE);

	const auto token = provider->getToken();

	BC_ASSERT_TRUE(token == nullopt);
}

} // namespace firebaseV1

namespace {
TestSuite _("Push notification access token provider",
            {TEST_NO_TAG("FirebaseV1AccessTokenProvider-instantiation-01",
                         firebaseV1::testInstantiateWrongPathToPythonScript),
     TEST_NO_TAG_AUTO_NAMED(firebaseV1::testGetTokenSuccess), TEST_NO_TAG_AUTO_NAMED(firebaseV1::testGetTokenError)});
} // namespace

} // namespace flexisip::tester