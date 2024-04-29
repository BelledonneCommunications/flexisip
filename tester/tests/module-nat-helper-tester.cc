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

#include "module-nat-helper.hh"

#include <exception>

#include "nat/contact-correction-strategy.hh"
#include "nat/flow-token-strategy.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {

/*
 * Test wrong contact url in "Contact" header is corrected in response.
 */
void wrongContactInResponse() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0"},
	    {"global/aliases", "localhost"},
	}};
	proxy.start();

	const pair<string, uint16_t> port{"1234", 1234};
	const pair<string, uint32_t> host{"1.2.3.4", 0x01020304};
	const auto expectedContactUrl = "sip:caller@" + host.first + ":" + port.first + ";transport=tcp";

	// Create a sip response event with transport corresponding to received "ip:port" in the first "VIA" header.
	const auto request =
	    "SIP/2.0 200 OK\r\n"
	    "Via: SIP/2.0/TCP sip.example.org;rport;branch=a;received=5.6.7.8\r\n"
	    "Via: SIP/2.0/TLS 10.0.0.8:56324;branch=b;rport=" +
	    port.first + ";received=" + host.first + "\r\n" +
	    "From: \"Callee\" <sip:callee@sip.example.org>;tag=Qx935r3\r\n"
	    "To: \"Caller\" <sip:caller@sip.example.org>;tag=fd983a4f\r\n"
	    "Contact: <sip:caller@sip.example.org;transport=tcp>\r\n"
	    "Call-ID: stub-call-id\r\n"
	    "CSeq: 113 INVITE\r\n"
	    "Session-Expires: 1800;refresher=uas\r\n"
	    "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK\r\n"
	    "Allow-Events: presence, refer, dialog\r\n"
	    "Accept: application/sdp\r\n"
	    "Accept-Encoding: identity\r\n"
	    "Accept-Language: en\r\n"
	    "Supported: 100rel, replaces, timer\r\n"
	    "User-Agent: stub-user-agent\r\n"
	    "Content-Type: application/sdp\r\n"
	    "Content-Length: 261";

	// Create sip message with "ip:port" corresponding to "received" in the first "VIA" header.
	const auto msg = make_shared<MsgSip>(0, request);
	auto* sockAddr = reinterpret_cast<sockaddr_in*>(msg->getSockAddr());
	sockAddr->sin_addr.s_addr = htonl(host.second);
	sockAddr->sin_port = htons(port.second);
	sockAddr->sin_family = AF_INET;

	// Create dummy incoming transport to make NatHelper::needToBeFixed return true.
	tp_name_t name{"tcp", nullptr, "localhost", "0", nullptr, nullptr};
	auto* incomingTport = tport_by_name(nta_agent_tports(proxy.getAgent()->getSofiaAgent()), &name);
	auto event = make_shared<ResponseSipEvent>(proxy.getAgent(), msg, incomingTport);

	const auto module = dynamic_pointer_cast<NatHelper>(proxy.getAgent()->findModule("NatHelper"));
	module->onResponse(event);

	const auto* contact = event->getSip()->sip_contact;
	BC_HARD_ASSERT(contact != nullptr);
	BC_ASSERT_CPP_EQUAL(url_as_string(event->getHome(), contact->m_url), expectedContactUrl);
}

void configurationValueNatTraversalStrategyContactCorrection() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"global/aliases", "localhost"},
	    {"module::NatHelper/nat-traversal-strategy", "contact-correction"},
	}};

	proxy.start();

	BC_ASSERT(dynamic_cast<ContactCorrectionStrategy*>(proxy.getAgent()->getNatTraversalStrategy().get()) != nullptr);
}

void configurationValueNatTraversalStrategyFlowToken() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"global/aliases", "localhost"},
	    {"module::NatHelper/nat-traversal-strategy", "flow-token"},
	}};

	proxy.start();

	BC_ASSERT(dynamic_cast<FlowTokenStrategy*>(proxy.getAgent()->getNatTraversalStrategy().get()) != nullptr);
}

void configurationValueNatTraversalStrategyWrongValue() {
	Server server{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"global/aliases", "localhost"},
	    {"module::NatHelper/nat-traversal-strategy", "unexpected"},
	}};

	BC_ASSERT_THROWN(server.start(), runtime_error);
}

/*
 * Test successful removal of custom contact url parameter when request goes through NatHelper::onResponse with
 * different `nat-traversal-strategy`s
 */
template <const char natTraversalStrategy[]>
void onResponseNatHelperRemoveContactCorrectionParameter() {
	const string contactCorrectionParameter = "parameter";
	Server proxy{{
	    {"module::NatHelper/nat-traversal-strategy", natTraversalStrategy},
	    {"module::NatHelper/contact-correction-param", contactCorrectionParameter},
	}};
	proxy.start();

	// Build response request where proxy is considered last hop.
	ostringstream request;
	request << "SIP/2.0 200 Ok\r\n"
	        << "Via: SIP/2.0/UDP 1.2.3.4;rport=5678;branch=stub-branch\r\n"
	        << "Via: SIP/2.0/UDP 5.6.7.8;rport=9123;branch=stub-branch\r\n"
	        << "From: <sip:caller@sip.example.org>;tag=stub-from-tag\r\n"
	        << "To: <sip:callee@sip.example.org>;tag=stub-to-tag\r\n"
	        << "Contact: <sip:caller@sip.example.org;transport=tcp;" << contactCorrectionParameter << ">\r\n"
	        << "Call-ID: stub-id\r\n"
	        << "CSeq: 20 INVITE\r\n"
	        << "User-Agent: stub-agent\r\n"
	        << "Content-Length: 0\r\n";

	const auto msg = make_shared<MsgSip>(0, request.str());
	auto event = make_shared<ResponseSipEvent>(proxy.getAgent(), msg, nullptr);
	BC_HARD_ASSERT(event->getSip()->sip_contact != nullptr);
	BC_ASSERT(url_has_param(event->getSip()->sip_contact->m_url, contactCorrectionParameter.c_str()) == true);

	dynamic_cast<NatHelper&>(*proxy.getAgent()->findModule("NatHelper")).onResponse(event);

	BC_ASSERT(url_has_param(event->getSip()->sip_contact->m_url, contactCorrectionParameter.c_str()) == false);
}

const char contactCorrection[] = "contact-correction";
const char flowToken[] = "flow-token";

TestSuite _("NatHelperModule",
            {
                CLASSY_TEST(wrongContactInResponse),
                CLASSY_TEST(configurationValueNatTraversalStrategyContactCorrection),
                CLASSY_TEST(configurationValueNatTraversalStrategyFlowToken),
                CLASSY_TEST(configurationValueNatTraversalStrategyWrongValue),
                CLASSY_TEST(onResponseNatHelperRemoveContactCorrectionParameter<contactCorrection>),
                CLASSY_TEST(onResponseNatHelperRemoveContactCorrectionParameter<flowToken>),
            });

} // namespace

} // namespace flexisip::tester