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

#include <chrono>

#include "flexisip-tester-config.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "pushnotification/firebase-v1/firebase-v1-authentication-manager.hh"
#include "pushnotification/firebase-v1/firebase-v1-request.hh"
#include "tester.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using HttpRequest = flexisip::HttpMessage;
using namespace flexisip::pushnotification;

namespace flexisip::tester {

namespace {

namespace firebaseV1 {

constexpr auto kPyScriptError = FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_error.py";
constexpr auto kPyScriptSuccess = FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success.py";
constexpr auto kPyScriptSuccessF = FLEXISIP_TESTER_DATA_SRCDIR "/scripts/firebase_v1_get_access_token_success_fixed.py";
constexpr auto kFirebaseSampleFile = FLEXISIP_TESTER_DATA_SRCDIR "/config/firebase_sample_service_account.json";

struct Helper {

	static shared_ptr<FirebaseV1AuthenticationManager>
	makeAuthenticationManager(const shared_ptr<sofiasip::SuRoot>& root, const filesystem::path& script) {
		return make_shared<FirebaseV1AuthenticationManager>(root, script, kFirebaseSampleFile, 10min, 10s);
	}

	static shared_ptr<HttpRequest> makeRequest(string_view projectId) {
		static const auto fakePushInfo = make_shared<flexisip::pushnotification::PushInfo>();
		static const auto fakeDestination = make_shared<RFC8599PushParams>("fcm", "", "device_id");

		fakePushInfo->addDestination(fakeDestination);
		fakePushInfo->mTtl = 42s;
		fakePushInfo->mUid = "stub-uid";
		fakePushInfo->mFromUri = "sip:sender@sip.linphone.org";

		return make_shared<FirebaseV1Request>(PushType::Background, fakePushInfo, projectId);
	}

	static constexpr auto findTokenInHeadersListFunc = [](const HttpHeaders::Header& header) {
		return header.name == "authorization";
	};
};

void testInstantiateWrongPathFirebaseServiceAccountFile() {
	const auto root = make_shared<sofiasip::SuRoot>();
	BC_ASSERT_THROWN(
	    make_shared<FirebaseV1AuthenticationManager>(root, kPyScriptSuccess, "wrong/path/to/file.json", 10min, 10s),
	    runtime_error);
}

void testInstantiateFailedToParseServiceAccountFile() {
	const auto root = make_shared<sofiasip::SuRoot>();
	const auto fp = FLEXISIP_TESTER_DATA_SRCDIR "/config/firebase_sample_service_account_error.json";
	BC_ASSERT_THROWN(make_shared<FirebaseV1AuthenticationManager>(root, kPyScriptSuccess, fp, 10min, 10s),
	                 runtime_error);
}

void testInstantiateMissingProjectIdServiceAccountFile() {
	const auto root = make_shared<sofiasip::SuRoot>();
	const auto path = FLEXISIP_TESTER_DATA_SRCDIR "/config/firebase_sample_service_account_missing_field.json";
	BC_ASSERT_THROWN(make_shared<FirebaseV1AuthenticationManager>(root, kPyScriptSuccess, path, 10min, 10s),
	                 runtime_error);
}

void testProjectId() {
	const auto root = make_shared<sofiasip::SuRoot>();
	const auto manager = Helper::makeAuthenticationManager(root, kPyScriptSuccess);

	const string projectId{manager->getProjectId()};
	BC_ASSERT_CPP_EQUAL(projectId, "sample-project");
}

void testAddAuthenticationSuccess() {
	const auto root = make_shared<sofiasip::SuRoot>();
	const auto manager = Helper::makeAuthenticationManager(root, kPyScriptSuccessF);
	const auto request = Helper::makeRequest(manager->getProjectId());

	BC_HARD_ASSERT(manager->addAuthentication(request) == true);

	const auto& list = request->getHeaders().getHeadersList();
	const auto it = find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc);

	BC_HARD_ASSERT(it != list.end());
	BC_ASSERT_CPP_EQUAL(it->value, "Bearer stub-token");
}

void testAddAuthenticationError() {
	auto root = make_shared<sofiasip::SuRoot>();
	const auto manager = Helper::makeAuthenticationManager(root, kPyScriptError);
	const auto request = Helper::makeRequest(manager->getProjectId());

	BC_HARD_ASSERT(manager->addAuthentication(request) == false);

	const auto& list = request->getHeaders().getHeadersList();
	const auto it = find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc);

	BC_ASSERT(it == list.end());
}

void testRefreshTokenSuccess() {
	const auto root = make_shared<sofiasip::SuRoot>();
	// The python script returns a lifetime of 42s, so we set the token expiration anticipation value to 41s.
	// Thus, the token refresh operation should run the next second.
	const auto manager =
	    make_shared<FirebaseV1AuthenticationManager>(root, kPyScriptSuccess, kFirebaseSampleFile, 10min, 41000ms);

	string token1{};
	string token2{};

	const auto request = Helper::makeRequest(manager->getProjectId());
	BC_HARD_ASSERT(manager->addAuthentication(request) == true);

	const auto& list = request->getHeaders().getHeadersList();
	token1 = find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc)->value;

	BC_HARD_ASSERT(!token1.empty());

	this_thread::sleep_for(750ms);
	sofiasip::Timer timer{root->getCPtr(), 50ms};
	const auto timeout = chrono::system_clock::now() + 2s;
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
	BC_HARD_ASSERT(token1.find("Bearer stub-token") != string::npos);
	SLOGD << "Token n°2 = " << token2;
	BC_HARD_ASSERT(token2.find("Bearer stub-token") != string::npos);
	BC_ASSERT(token1 != token2);
}

void testRefreshTokenError() {
	const auto root = make_shared<sofiasip::SuRoot>();
	const auto manager =
	    make_shared<FirebaseV1AuthenticationManager>(root, kPyScriptError, kFirebaseSampleFile, 50ms, 100s);
	const auto request = Helper::makeRequest(manager->getProjectId());
	BC_HARD_ASSERT(manager->addAuthentication(request) == false);

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
	BC_ASSERT(find_if(list.begin(), list.end(), Helper::findTokenInHeadersListFunc) == list.end());
}

} // namespace firebaseV1

TestSuite _("pushnotification::AuthenticationManager",
            {
                CLASSY_TEST(firebaseV1::testInstantiateWrongPathFirebaseServiceAccountFile),
                CLASSY_TEST(firebaseV1::testInstantiateFailedToParseServiceAccountFile),
                CLASSY_TEST(firebaseV1::testInstantiateMissingProjectIdServiceAccountFile),
                CLASSY_TEST(firebaseV1::testProjectId),
                CLASSY_TEST(firebaseV1::testAddAuthenticationSuccess),
                CLASSY_TEST(firebaseV1::testAddAuthenticationError),
                CLASSY_TEST(firebaseV1::testRefreshTokenSuccess),
                CLASSY_TEST(firebaseV1::testRefreshTokenError),
            });

} // namespace

} // namespace flexisip::tester
