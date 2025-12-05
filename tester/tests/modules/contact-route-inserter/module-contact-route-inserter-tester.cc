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

#include "modules/module-contact-route-inserter.hh"

#include "transaction/incoming-transaction.hh"
#include "utils/asserts.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tls/certificate.hh"
#include "utils/tls/private-key.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

struct MasqueradeTestConfig {
	string transports{};     // Content of Proxy global/transports parameter.
	SipUri userContactUri{}; // The URI inserted in the 'Contact' header field.
	SipUri::Scheme scheme{}; // The scheme to use in the REGISTER request URI (it has an impact on the selected outgoing
	                         // transport, thus modifying the contact masquerading operation).
};

/**
 * Test contact masquerading.
 * The module is expected to rewrite the contact using information from the most appropriate outgoing transport
 * (computed by sofia-sip).
 */
void masqueradeContactHeaderField(const MasqueradeTestConfig& config,
                                  const function<SipUri(const tport_t* tport)>& getExpectedOutgoingTransport,
                                  const std::string& expectedCtRtParameter) {
	const auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	const TlsCertificate certificate{privateKey};
	privateKey.writeToFile(keyPath);
	certificate.writeToFile(certPath);

	Server proxy{{
	    {"global/transports", config.transports},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	    {"module::ContactRouteInserter/enabled", "true"},
	}};
	proxy.start();

	bool callbacksCalled{};
	const auto agent = proxy.getAgent();
	const auto incoming = make_shared<IncomingTransaction>(agent);

	stringstream request{};
	request << "REGISTER " << url_scheme(static_cast<url_type_e>(config.scheme)) << ":127.0.0.2:4862 SIP/2.0\r\n"
	        << "From: <" << config.userContactUri.replacePort("").str() << ">;tag=stub-tag\r\n"
	        << "To: <" << config.userContactUri.replacePort("").str() << ">\r\n"
	        << "Call-ID: stub-call-id\r\n"
	        << "CSeq: 20 REGISTER\r\n"
	        << "Contact: <" << config.userContactUri.str() << ">\r\n"
	        << "Expires: 600\r\n"
	        << "Content-Length: 0\r\n\r\n";
	const auto msg = make_shared<MsgSip>(0, request.str());

	const auto module = dynamic_pointer_cast<ContactRouteInserter>(agent->findModuleByRole("ContactRouteInserter"));
	BC_HARD_ASSERT(module != nullptr);

	RequestSipEvent event{incoming, msg};
	event.createOutgoingTransaction();
	event.addBeforeSendCallback([&](const shared_ptr<MsgSip>&, const tport_t*) { callbacksCalled = true; });
	module->onRequest(event);
	event.send(msg);

	CoreAssert{proxy}.wait([&] { return LOOP_ASSERTION(callbacksCalled == true); }).hard_assert_passed();

	SLOGD << "After:\n" << *msg;

	auto* contact = msg->getSip()->sip_contact;
	BC_HARD_ASSERT(contact != nullptr);

	const SipUri uri{contact->m_url};
	// Compare to proxy transport.
	const auto expectedTransport = getExpectedOutgoingTransport(proxy.getFirstTransport(AF_INET));
	BC_ASSERT_ENUM_EQUAL(uri.getSchemeType(), expectedTransport.getSchemeType());
	BC_ASSERT_CPP_EQUAL(uri.getHost(), expectedTransport.getHost());
	BC_ASSERT_CPP_EQUAL(uri.getPort(), expectedTransport.getPort());
	BC_ASSERT_CPP_EQUAL(uri.getParam("transport"), expectedTransport.getParam("transport"));

	BC_ASSERT_CPP_EQUAL(uri.getParam(module->getContactRouteParamName()), expectedCtRtParameter);

	// There should be no more contact.
	BC_ASSERT(contact->m_next == nullptr);
}

const SipUri kTransport1{"sip:127.0.0.1:0;network=127.0.0.0/24"};
const SipUri kTransport2{"sips:sip.example.org:0;maddr=127.0.0.1"};

void masqueradeContactHeaderFieldSipOutgoingTransport() {
	const SipUri user{"sip:user@sip.backend.example.org:1324"};
	const string expectedCtRtParameter = "udp:" + user.getHost() + ":"s + user.getPort().data();
	masqueradeContactHeaderField(
	    {
	        kTransport1.str() + " "s + kTransport2.str(),
	        user,
	        SipUri::Scheme::sip,
	    },
	    [](const tport_t* primaries) { return kTransport1.replacePort(tport_name(primaries)->tpn_port); },
	    expectedCtRtParameter);
	// Testing a second time inverting transports declaration order to make sure the outgoing transport selection is
	// still correct and that masquerading worked successfully.
	masqueradeContactHeaderField(
	    {
	        kTransport2.str() + " "s + kTransport1.str(),
	        user,
	        SipUri::Scheme::sip,
	    },
	    [](const tport_t* primaries) { return kTransport1.replacePort(tport_name(tport_next(primaries))->tpn_port); },
	    expectedCtRtParameter);
}

void masqueradeContactHeaderFieldSipsOutgoingTransport() {
	const SipUri user{"sips:user@sip.backend.example.org:1324"};
	const string expectedCtRtParameter = "tls:" + user.getHost() + ":"s + user.getPort().data();
	masqueradeContactHeaderField(
	    {
	        kTransport1.str() + " "s + kTransport2.str(),
	        user,
	        SipUri::Scheme::sips,
	    },
	    [](const tport_t* primaries) {
		    return kTransport2.replacePort(tport_name(tport_next(tport_next(primaries)))->tpn_port);
	    },
	    expectedCtRtParameter);
	// Testing a second time inverting transports declaration order to make sure the outgoing transport selection is
	// still correct and that masquerading worked successfully.
	masqueradeContactHeaderField(
	    {
	        kTransport2.str() + " "s + kTransport1.str(),
	        user,
	        SipUri::Scheme::sips,
	    },
	    [](const tport_t* primaries) { return kTransport2.replacePort(tport_name(primaries)->tpn_port); },
	    expectedCtRtParameter);
}

TestSuite _{
    "ModuleContactRouteInserter",
    {
        CLASSY_TEST(masqueradeContactHeaderFieldSipOutgoingTransport),
        CLASSY_TEST(masqueradeContactHeaderFieldSipsOutgoingTransport),
    },
};

} // namespace
} // namespace flexisip::tester