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

#include <string>

#include "sofia-wrapper/nta-agent.hh"
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;
using namespace flexisip;
using namespace flexisip::tester;

namespace {
// Register with a valid client TLS certificate
void acceptRegister() {
	TempFile authFile("version:1\n");
	auto caFile = bcTesterRes("cert/self.signed.ca.pem");

	Server proxy{{
	    {"global/transports", "sips:127.0.0.1:0;tls-verify-incoming=1"},
	    {"global/tls-certificates-ca-file", caFile},
	    {"global/tls-certificates-file", bcTesterRes("cert/self.signed.cert.test.pem")},
	    {"global/tls-certificates-private-key", bcTesterRes("cert/self.signed.key.test.pem")},
	    {"module::Registrar/reg-domains", "*"},
	    {"module::Authentication/enabled", "true"},
	    {"module::Authentication/file-path", authFile.getFilename()},
	    {"module::Authentication/auth-domains", "tester.example.org"},
	    {"module::Authentication/trust-domain-certificates", "true"},
	}};
	proxy.start();

	const auto sipUri = "sips:user@tester.example.org";
	// clang-format off
	const auto request = std::string(
		std::string("REGISTER ") + sipUri+ " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: <" + sipUri + ">\r\n"
		"From: <" + sipUri + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 3 REGISTER\r\n"
		"Contact: <" + sipUri + ";>;+sip.instance=fcm1Reg\r\n"
		"Expires: 60\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	NtaAgent client(proxy.getRoot(), nullptr);
	const auto clientCert = bcTesterRes("cert/tester.example.org/tester-crt.pem");
	const auto clientKey = bcTesterRes("cert/tester.example.org/tester-key.pem");
	const auto* ciphers = "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL";
	client.addTransport("sips:127.0.0.1:0;transport=tls", TPTAG_CERTIFICATE_FILE(clientCert.c_str()),
	                    TPTAG_CERTIFICATE_PRIVATE_KEY(clientKey.c_str()), TPTAG_CERTIFICATE_CA_FILE(caFile.c_str()),
	                    TPTAG_TLS_VERIFY_POLICY(tport_tls_verify_policy::TPTLS_VERIFY_NONE),
	                    TPTAG_TLS_CIPHERS(ciphers));
	const auto transaction =
	    client.createOutgoingTransaction(request, std::string("sips:127.0.0.1:") + proxy.getFirstPort());

	CoreAssert(proxy)
	    .iterateUpTo(
	        0x20, [&transaction] { return LOOP_ASSERTION(transaction->isCompleted()); }, 100ms)
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 200);
}

TestSuite _("AuthTlsClient",
            {
                CLASSY_TEST(acceptRegister),
            });
} // namespace