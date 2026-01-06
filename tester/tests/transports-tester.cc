/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/sofia-wrapper/su-root.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/server/injected-module-info.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

#include <fstream>

using namespace std;

namespace flexisip::tester {

namespace {

// Check that the proxy does not start without certificates
void mandatoryCertificatesForServer() {
	auto root = make_shared<sofiasip::SuRoot>();

	Server proxyDefaultCertificatesMissing({
	    {"global/transports", "sips:127.0.0.1:0"},
	    {"module::Registrar/reg-domains", "*"},
	});

	BC_ASSERT_THROWN(proxyDefaultCertificatesMissing.start(), runtime_error);

	Server proxyExplicitlyWithoutCertificates({
	    {"global/transports", "sips:127.0.0.1:0"},
	    {"global/tls-certificates-dir", ""},
	    {"global/tls-certificates-file", ""},
	    {"global/tls-certificates-private-key", ""},
	});

	BC_ASSERT_THROWN(proxyExplicitlyWithoutCertificates.start(), runtime_error);

	const auto certFilePath = bcTesterRes("cert/self.signed.cert.test.pem");
	const auto keyFilePath = bcTesterRes("cert/self.signed.key.test.pem");

	Server proxyWithCertificates({
	    {"global/transports", "sips:127.0.0.1:0"},
	    {"global/tls-certificates-file", certFilePath},
	    {"global/tls-certificates-private-key", keyFilePath},
	});
	try {
		proxyWithCertificates.start();
	} catch (exception& e) {
		BC_FAIL("Unexpected exeption: " + e.what());
	}
}

// Check that client transports do not need certificates
void clientTransport() {
	Server clientProxy{
	    {
	        {"global/transports", "sips:127.0.0.1:0;tls-client-connection=1"},
	        {"global/tls-certificates-dir", ""},
	        {"global/tls-certificates-file", ""},
	        {"global/tls-certificates-private-key", ""},
	    },
	};

	try {
		clientProxy.start();
	} catch (exception& e) {
		BC_FAIL("Unexpected exeption: " + e.what());
	}
}

TestSuite _("transports",
            {
                CLASSY_TEST(mandatoryCertificatesForServer),
                CLASSY_TEST(clientTransport),
            });
} // namespace
} // namespace flexisip::tester