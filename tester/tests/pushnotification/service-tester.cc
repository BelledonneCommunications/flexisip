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

#include "pushnotification/service.hh"

#include <fstream>

#include "flexisip/sofia-wrapper/su-root.hh"

#include "flexisip-tester-config.hh"
#include "tester.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

namespace {
using namespace flexisip::tester;
using namespace flexisip::pushnotification;
using namespace sofiasip;
using namespace std;

void setupiOSClient__bad_certificate_does_not_crash() {
	const auto stubRoot = make_shared<SuRoot>();
	Service service{stubRoot, 0xdead};
	TmpDir certDir{".certificates.d"};
	ofstream badCertFile{certDir.path() / "bad-cert.pem"};
	badCertFile << "I'd like to speak to your manager >:(";

	service.setupiOSClient(certDir.path(), bcTesterRes("cert/apple.test.dev.pem"));
}

/**
 * This checks that a new AppleClient will be created, upon receiving a request to send a push notification, if a
 * corresponding certificate has been added.
 */
void createAppleClientFromPotentialNewCertificate__valid_certificate_added() {
	const auto stubRoot = make_shared<SuRoot>();
	Service service{stubRoot, 0xdead};

	const auto validCertPath = bcTesterResourceDir() / "cert/apple.test.dev.pem";
	// Create empty dir
	TmpDir certDir{".certificates.d"};
	service.setupiOSClient(certDir.path(), "");

	const auto pushType = PushType::Message;
	auto pushInfo = make_shared<PushInfo>();
	auto pushParams = make_shared<RFC8599PushParams>("apns.dev", ".someAppId", string(64, 'a'));
	pushInfo->addDestination(pushParams);

	// Ensure that no request can currently be made, since there is no certificate
	BC_ASSERT_THROWN(service.makeRequest(pushType, pushInfo), UnavailablePushNotificationClient)
	// Add a valid certificate
	std::filesystem::copy_file(validCertPath, certDir.path() / "someAppId.dev.pem");
	// Try making a request again to verify that the new certificate is used
	const auto req = service.makeRequest(pushType, pushInfo);
	BC_ASSERT_PTR_NOT_NULL(req);

	BC_ASSERT_CPP_EQUAL(service.getClients().size(), 1);
}

TestSuite _("pushnotification::Service",
            {
                CLASSY_TEST(setupiOSClient__bad_certificate_does_not_crash),
                CLASSY_TEST(createAppleClientFromPotentialNewCertificate__valid_certificate_added),
            });
} // namespace
