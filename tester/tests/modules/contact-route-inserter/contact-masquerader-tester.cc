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

#include "contact-masquerader.hh"

#include "sofia-sip/url.h"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/asserts.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

constexpr bool kUsingDomainInFrom = true;
constexpr bool kUsingHostPortInContact = false;
constexpr auto kCtRtParamName = "CtRtstubuniqueid";

template <const bool insertDomain>
void masqueradeRegisterRequest() {
	const string username{"user"};
	const string domain{"localhost"};
	const string identity{username + "@" + domain};

	const auto root = make_shared<SuRoot>();
	// Note: this agent only exists to create a tport_t instance.
	const NtaAgent master{root, "sip:" + identity + ":0;transport=tcp", nullptr, nullptr};

	const SipUri contact1{"sip:" + identity + ":1234"};
	const SipUri contact2{"sip:" + identity + ":5678"};
	const SipUri contact3{"sips:" + identity + ":9123"};
	const SipUri contact4{"sip:" + identity + ":4567;transport=tcp"};

	stringstream request{};
	request << "REGISTER sip:localhost SIP/2.0\r\n"
	        << "From: <sip:" << identity << ">;tag=stub-tag\r\n"
	        << "To: <sip:" << identity << ">\r\n"
	        << "Call-ID: stub-call-id\r\n"
	        << "CSeq: 20 REGISTER\r\n"
	        << "Contact: <" << contact1 << ">\r\n"
	        << "Contact: <" << contact2 << ">;expires=0\r\n"
	        << "Contact: <" << contact3 << ">\r\n"
	        << "Contact: <" << contact4 << ">\r\n"
	        << "Expires: 600\r\n"
	        << "Content-Length: 0\r\n\r\n";

	MsgSip msg{0, request.str()};
	const auto* transport = tport_primaries(master.getTransports());
	const auto transportUri = SipUri::fromName(tport_name(transport));

	SLOGD << "Transport: " << transportUri.str();
	SLOGD << "Before:\n" << msg.msgAsString();

	contact_masquerader::masquerade(msg, kCtRtParamName, transport, insertDomain);

	SLOGD << "After:\n" << msg.msgAsString();

	const auto makeContactRouteParameter = [](const SipUri& uri) {
		string protocol{};
		if (uri.getSchemeType() == SipUri::Scheme::sips) protocol = "tls";
		else protocol = uri.hasParam("transport") ? uri.getParam("transport") : "udp";
		return protocol + ":" + uri.getHost() + (insertDomain ? "" : (":"s + uri.getPortWithFallback().data()));
	};

	auto* contact = msg.getSip()->sip_contact;
	BC_HARD_ASSERT(contact != nullptr);

	// Note: contact2 gets removed because of 'expires=0'.
	for (const auto& contactInRegister : {contact1, contact3, contact4}) {
		const SipUri uri{contact->m_url};

		BC_ASSERT_ENUM_EQUAL(uri.getSchemeType(), transportUri.getSchemeType());
		BC_ASSERT_CPP_EQUAL(uri.getHost(), transportUri.getHost());
		BC_ASSERT_CPP_EQUAL(uri.getPort(), transportUri.getPort());
		BC_ASSERT_CPP_EQUAL(uri.getParam("transport"), transportUri.getParam("transport"));

		BC_ASSERT_CPP_EQUAL(uri.getParam(kCtRtParamName), makeContactRouteParameter(contactInRegister));

		if (contact->m_next != nullptr) contact = contact->m_next;
	}

	// There should be no more contact.
	BC_HARD_ASSERT(contact != nullptr);
	BC_ASSERT(contact->m_next == nullptr);
}

void restoreDomain() {
	Home home{};
	auto* destination = url_make(home.home(), "sip:user@proxy.example.org:5062;transport=tcp;maddr=proxy.example.org");
	url_param_add(home.home(), destination, kCtRtParamName);
	BC_HARD_ASSERT(destination != nullptr);

	contact_masquerader::restore(home.home(), destination, kCtRtParamName, "udp:managed.example.org", "doroute");

	const SipUri restored{destination};
	BC_ASSERT_CPP_EQUAL(restored.getHost(), "managed.example.org");
	BC_ASSERT(restored.getPort().empty());
	BC_ASSERT_FALSE(restored.hasParam(kCtRtParamName));
	BC_ASSERT_FALSE(restored.hasParam("maddr"));
	BC_ASSERT_FALSE(restored.hasParam("transport"));
	BC_ASSERT_TRUE(restored.hasParam("doroute"));
}

void restoreHostPort() {
	Home home{};
	auto* destination = url_make(home.home(), "sip:user@proxy.example.org:5062;transport=udp;maddr=proxy.example.org");
	url_param_add(home.home(), destination, kCtRtParamName);
	BC_HARD_ASSERT(destination != nullptr);

	contact_masquerader::restore(home.home(), destination, kCtRtParamName, "tcp:10.0.0.10:5070", "doroute");

	const SipUri restored{destination};
	BC_ASSERT_CPP_EQUAL(restored.getHost(), "10.0.0.10");
	BC_ASSERT_CPP_EQUAL(restored.getPort(), "5070");
	BC_ASSERT_CPP_EQUAL(restored.getParam("transport"), "tcp");
	BC_ASSERT_FALSE(restored.hasParam(kCtRtParamName));
	BC_ASSERT_FALSE(restored.hasParam("maddr"));
	BC_ASSERT_TRUE(restored.hasParam("doroute"));
}

void restoreRejectsMalformedParameter() {
	for (const auto& param : {"udp", "udp:host:5060:extra", "udp:", ":host", "udp:host:"}) {
		Home home{};
		auto* destination =
		    url_make(home.home(), "sip:user@proxy.example.org:5062;transport=tcp;maddr=proxy.example.org");
		url_param_add(home.home(), destination, kCtRtParamName);
		BC_HARD_ASSERT(destination != nullptr);
		const SipUri before{destination};

		contact_masquerader::restore(home.home(), destination, kCtRtParamName, param, "doroute");

		const SipUri after{destination};
		BC_ASSERT_TRUE(before.compareAll(after));
	}
}

TestSuite _{
    "ContactMasquerader",
    {
        CLASSY_TEST(masqueradeRegisterRequest<kUsingDomainInFrom>),
        CLASSY_TEST(masqueradeRegisterRequest<kUsingHostPortInContact>),
        CLASSY_TEST(restoreDomain),
        CLASSY_TEST(restoreHostPort),
        CLASSY_TEST(restoreRejectsMalformedParameter),
    },
};

} // namespace
} // namespace flexisip::tester