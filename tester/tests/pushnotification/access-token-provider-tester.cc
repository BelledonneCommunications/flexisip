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

#include "flexisip-tester-config.hh"

#include "pushnotification/firebase-v1/firebase-v1-access-token-provider.hh"
#include "pushnotification/firebase-v1/firebase-v1-authentication-manager.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

#define PY_SCRIPT_ERROR FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_error.py"
#define PY_SCRIPT_SUCCESS_F FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success_fixed.py"
#define PY_SCRIPT_UNEXPECTED_OUTPUT                                                                                    \
	FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_unexpected_output.py"
#define FIREBASE_SAMPLE_FILE FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/config/firebase_sample_service_account.json"

using namespace std;
using HttpRequest = flexisip::HttpMessage;
using namespace flexisip::pushnotification;

namespace flexisip::tester {

namespace {

namespace firebaseV1 {

void makeAccessTokenProviderWithWrongPathToPythonScript() {
	BC_ASSERT_THROWN(FirebaseV1AccessTokenProvider("wrong/path/to/script.py", FIREBASE_SAMPLE_FILE), runtime_error);
}

void runScriptFailedToParseScriptOutput() {
	const FirebaseV1AccessTokenProvider provider{PY_SCRIPT_SUCCESS_F, "&& pollute-script-output"};

	const auto output = provider.runScript();

	BC_HARD_ASSERT_CPP_EQUAL(output.at("state"), "ERROR");
	BC_ASSERT_CPP_EQUAL(output.at("data").at("message"), "failed to parse script output [exit_code = 127]");
}

void runScriptCaughtWarnings() {
	const FirebaseV1AccessTokenProvider provider{PY_SCRIPT_SUCCESS_F, FIREBASE_SAMPLE_FILE};

	const auto output = provider.runScript();

	BC_ASSERT(output.at("warnings").front() == "stub-warning-message");
}

void getTokenSuccess() {
	FirebaseV1AccessTokenProvider provider{PY_SCRIPT_SUCCESS_F, FIREBASE_SAMPLE_FILE};

	const auto token = provider.getToken();

	BC_HARD_ASSERT(token != nullopt);
	BC_ASSERT(token->lifetime == 42s);
	BC_ASSERT_CPP_EQUAL(token->content, "stub-token");
}

void getTokenUnexpectedJsonData() {
	FirebaseV1AccessTokenProvider provider{PY_SCRIPT_UNEXPECTED_OUTPUT, FIREBASE_SAMPLE_FILE};

	const auto token = provider.getToken();

	BC_ASSERT(token == nullopt);
}

void getTokenError() {
	FirebaseV1AccessTokenProvider provider{PY_SCRIPT_ERROR, FIREBASE_SAMPLE_FILE};

	const auto token = provider.getToken();

	BC_ASSERT(token == nullopt);
}

} // namespace firebaseV1

TestSuite _("pushnotification::AccessTokenProvider",
            {
                CLASSY_TEST(firebaseV1::makeAccessTokenProviderWithWrongPathToPythonScript),
                CLASSY_TEST(firebaseV1::runScriptFailedToParseScriptOutput),
                CLASSY_TEST(firebaseV1::runScriptCaughtWarnings),
                CLASSY_TEST(firebaseV1::getTokenSuccess),
                CLASSY_TEST(firebaseV1::getTokenUnexpectedJsonData),
                CLASSY_TEST(firebaseV1::getTokenError),
            });

} // namespace

} // namespace flexisip::tester