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

#include "modules/module-toolbox.hh"

#include <functional>

#include "flexisip/module-router.hh"
#include "flexisip/utils/sip-uri.hh"
#include "tester.hh"
#include "utils/bellesip-utils.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-suite.hh"
#include "utils/tls/certificate.hh"
#include "utils/tls/private-key.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

namespace flexisip::tester {
namespace {

void addRecordRoute(SipUri::Scheme scheme) {
	const auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	const TlsCertificate certificate{privateKey};
	privateKey.writeToFile(keyPath);
	certificate.writeToFile(certPath);

	Server proxy{{
	    {"global/transports", scheme == SipUri::Scheme::sips ? "sips:127.0.0.1:0" : "sip:127.0.0.1:0"},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	}};
	proxy.start();
	const auto& agent = proxy.getAgent();
	auto* transport = proxy.getFirstTransport(AF_INET);

	stringstream request{};
	request << "INVITE sip:user@localhost SIP/2.0\r\n"
	        << "To: <sip:user@localhost>\r\n"
	        << "From: <sip:anthony@localhost>;tag=stub-tag\r\n"
	        << "Call-ID: stub-call-id\r\n"
	        << "CSeq: 20 INVITE\r\n"
	        << "Contact: <sip:user@localhost>\r\n"
	        << "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n\r\n";
	const auto msg = make_shared<MsgSip>(0, request.str());

	SLOGD << "Before:\n" << *msg;
	module_toolbox::addRecordRoute(agent.get(), *msg, transport);
	SLOGD << "After:\n" << *msg;

	const auto expected = "Record-Route: <"s + url_scheme(static_cast<url_type_e>(scheme)) +
	                      ":127.0.0.1:" + proxy.getFirstPort() + ";lr>";
	BC_ASSERT(msg->msgAsString().find(expected) != std::string::npos);
}

void sipAddRecordRoute() {
	addRecordRoute(SipUri::Scheme::sip);
}

void sipsAddRecordRoute() {
	addRecordRoute(SipUri::Scheme::sips);
}

void isPrivateAddress() {
	BC_ASSERT(module_toolbox::isPrivateAddress("10.0.0.1") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("10.255.255.255") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.16.132.12") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.25.46.55") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.31.224.188") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("192.168.0.2") == true);
	BC_ASSERT(module_toolbox::isPrivateAddress("192.168.100.42") == true);

	BC_ASSERT(module_toolbox::isPrivateAddress("0.0.0.0") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("1.2.3.4") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("127.0.0.1") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.15.0.1") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("172.32.0.1") == false);
	BC_ASSERT(module_toolbox::isPrivateAddress("255.255.255.255") == false);
}

TestSuite _{
    "module_toolbox",
    {
        CLASSY_TEST(sipAddRecordRoute),
        CLASSY_TEST(sipsAddRecordRoute),
        CLASSY_TEST(isPrivateAddress),
    },
};

} // namespace
} // namespace flexisip::tester