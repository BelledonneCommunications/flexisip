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

#include "flexisip-tester-config.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "pushnotification/firebase-v1/firebase-v1-authentication-manager.hh"
#include "pushnotification/firebase-v1/firebase-v1-request.hh"
#include "tester.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

#define PY_SCRIPT_ERROR FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_error.py"
#define PY_SCRIPT_SUCCESS FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py"
#define PY_SCRIPT_SUCCESS_F FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success_fixed.py"
#define FIREBASE_SAMPLE_FILE FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/config/firebase_sample_service_account.json"

using namespace std;
using HttpRequest = flexisip::HttpMessage;

namespace flexisip::tester {
using namespace pushnotification;

namespace firebaseV1 {

namespace Helper {

static shared_ptr<FirebaseV1AuthenticationManager> authenticationManager(const std::shared_ptr<sofiasip::SuRoot>& root,
                                                                         const std::filesystem::path& script) {
	return make_shared<FirebaseV1AuthenticationManager>(root, script, FIREBASE_SAMPLE_FILE, 10min, 10s);
}

static shared_ptr<HttpRequest> request(std::string_view projectId) {
	static const auto fakeDestination = make_shared<RFC8599PushParams>("fcm", "", "device_id");
	static const auto fakePushInfo = make_shared<flexisip::pushnotification::PushInfo>();

	fakePushInfo->addDestination(fakeDestination);
	fakePushInfo->mTtl = 42s;
	fakePushInfo->mUid = "a-uuid-42";
	fakePushInfo->mFromUri = "sip:test@sip.linphone.org";

	return make_shared<FirebaseV1Request>(PushType::Background, fakePushInfo, projectId);
}

static const auto findTokenInHeadersListFunc = [](const HttpHeaders::Header& header) {
	return header.name == "authorization";
};

} // namespace Helper

void testInstantiateWrongPathFirebaseServiceAccountFile() {
	auto root = make_shared<sofiasip::SuRoot>();
	BC_ASSERT_THROWN(
	    make_shared<FirebaseV1AuthenticationManager>(root, PY_SCRIPT_SUCCESS, "wrong/path/to/file.json", 10min, 10s),
	    std::runtime_error);
}

void testInstantiateFailedToParseServiceAccountFile() {
	auto root = make_shared<sofiasip::SuRoot>();
	const auto fp = FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/config/firebase_sample_service_account_error.json";
	BC_ASSERT_THROWN(make_shared<FirebaseV1AuthenticationManager>(root, PY_SCRIPT_SUCCESS, fp, 10min, 10s),
	                 std::runtime_error);
}

void testInstantiateMissingProjectIdServiceAccountFile() {
	auto root = make_shared<sofiasip::SuRoot>();
	const auto fp = FLEXISIP_TESTER_INSTALL_DATA_SRCDIR "/config/firebase_sample_service_account_missing_field.json";
	BC_ASSERT_THROWN(make_shared<FirebaseV1AuthenticationManager>(root, PY_SCRIPT_SUCCESS, fp, 10min, 10s),
	                 std::runtime_error);
}

void testProjectId() {
	auto root = make_shared<sofiasip::SuRoot>();
	const auto manager = Helper::authenticationManager(root, PY_SCRIPT_SUCCESS);

	const string projectId(manager->getProjectId());
	BC_ASSERT_CPP_EQUAL(projectId, "sample-project");
}

void testAddAuthenticationSuccess() {
	auto root = make_shared<sofiasip::SuRoot>();
	const auto manager = Helper::authenticationManager(root, PY_SCRIPT_SUCCESS_F);
	const auto request = Helper::request(manager->getProjectId());

	BC_HARD_ASSERT_TRUE(manager->addAuthentication(request) == true);

	const auto& list = request->getHeaders().getHeadersList();
	const auto it = find_if(list.begin(), list.end(),
	                        [](const HttpHeaders::Header& header) { return header.name == "authorization"; });

	BC_HARD_ASSERT(it != list.end());
	BC_ASSERT_CPP_EQUAL(it->value, "Bearer THIS_IS_AN_ACCESS_TOKEN");
}

void testAddAuthenticationError() {
	auto root = make_shared<sofiasip::SuRoot>();
	const auto manager = Helper::authenticationManager(root, PY_SCRIPT_ERROR);
	const auto request = Helper::request(manager->getProjectId());

	BC_HARD_ASSERT_TRUE(manager->addAuthentication(request) == false);

	const auto& list = request->getHeaders().getHeadersList();
	const auto it = find_if(list.begin(), list.end(),
	                        [](const HttpHeaders::Header& header) { return header.name == "authorization"; });

	BC_ASSERT(it == list.end());
}

void testRefreshTokenSuccess() {
	auto root = make_shared<sofiasip::SuRoot>();
	// The python script returns a lifetime of 42s, so we set the token expiration anticipation value to 41s.
	// Thus, the token refresh operation should run the next second.
	const auto manager =
	    make_shared<FirebaseV1AuthenticationManager>(root, PY_SCRIPT_SUCCESS, FIREBASE_SAMPLE_FILE, 10min, 41000ms);

	std::string token1;
	std::string token2;

	const auto request = Helper::request(manager->getProjectId());
	BC_HARD_ASSERT_TRUE(manager->addAuthentication(request) == true);

	const auto& list = request->getHeaders().getHeadersList();
	token1 = find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc)->value;

	BC_HARD_ASSERT_TRUE(!token1.empty());

	this_thread::sleep_for(750ms);
	sofiasip::Timer timer{root->getCPtr(), 50ms};
	auto timeout = chrono::system_clock::now() + 2s;
	timer.run([&root, &manager, &request, &token1, &token2, &timeout]() {
		if (manager->addAuthentication(request)) {
			const auto& list = request->getHeaders().getHeadersList();
			token2 = find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc)->value;
			if (!token2.empty() and token2 != token1) {
				root->quit();
			}
		}

		if (timeout < chrono::system_clock::now()) {
			SLOGW << "Reached timeout";
			root->quit();
		}
	});
	root->run();

	SLOGD << "Token n°1 = " << token1;
	BC_HARD_ASSERT_TRUE(token1.find("Bearer TOKEN-") != string::npos);
	SLOGD << "Token n°2 = " << token2;
	BC_HARD_ASSERT_TRUE(token2.find("Bearer TOKEN-") != string::npos);
	BC_HARD_ASSERT_TRUE(token1 != token2);
}

void testRefreshTokenError() {
	auto root = make_shared<sofiasip::SuRoot>();
	auto manager =
	    make_shared<FirebaseV1AuthenticationManager>(root, PY_SCRIPT_ERROR, FIREBASE_SAMPLE_FILE, 50ms, 100s);
	const auto request = Helper::request(manager->getProjectId());
	BC_HARD_ASSERT_TRUE(manager->addAuthentication(request) == false);

	sofiasip::Timer timer{root->getCPtr(), 50ms};
	auto timeout = chrono::system_clock::now() + 200ms;
	timer.run([&root, &manager, &request, &timeout]() {
		if (manager->addAuthentication(request)) {
			SLOGW << "Authentication successfully added, this was not expected";
			root->quit();
		}

		if (timeout < chrono::system_clock::now()) {
			SLOGD << "Successfully reached timeout";
			root->quit();
		}
	});
	root->run();

	const auto& list = request->getHeaders().getHeadersList();
	BC_ASSERT_TRUE(find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc) == list.end());
}

} // namespace firebaseV1

namespace {
TestSuite _("Push notification authentication manager",
            {TEST_NO_TAG("FirebaseV1AuthenticationManager-instantiation-01",
                         firebaseV1::testInstantiateWrongPathFirebaseServiceAccountFile),
             TEST_NO_TAG("FirebaseV1AuthenticationManager-instantiation-02",
                         firebaseV1::testInstantiateFailedToParseServiceAccountFile),
             TEST_NO_TAG("FirebaseV1AuthenticationManager-instantiation-03",
                         firebaseV1::testInstantiateMissingProjectIdServiceAccountFile),
             TEST_NO_TAG_AUTO_NAMED(firebaseV1::testProjectId),
             TEST_NO_TAG_AUTO_NAMED(firebaseV1::testAddAuthenticationSuccess),
             TEST_NO_TAG_AUTO_NAMED(firebaseV1::testAddAuthenticationError),
             TEST_NO_TAG_AUTO_NAMED(firebaseV1::testRefreshTokenSuccess),
             TEST_NO_TAG_AUTO_NAMED(firebaseV1::testRefreshTokenError)});

} // namespace

} // namespace flexisip::tester
