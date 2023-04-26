/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "pushnotification/service.hh"

#include <fstream>

#include "flexisip/sofia-wrapper/su-root.hh"

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
	SuRoot stubRoot{};
	Service service{stubRoot, 0xdead};
	TmpDir certDir{".certificates.d"};
	ofstream badCertFile{certDir.path() / "bad-cert.pem"};
	badCertFile << "I'd like to speak to your manager >:(";

	service.setupiOSClient(certDir.path(), bcTesterRes("cert/apple.test.dev.pem"));
}

TestSuite _("pushnotification::Service",
            {
                CLASSY_TEST(setupiOSClient__bad_certificate_does_not_crash),
            });
} // namespace
