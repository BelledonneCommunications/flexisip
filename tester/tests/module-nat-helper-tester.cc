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

#include <bctoolbox/tester.h>
#include <sofia-sip/msg_addr.h>

#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

class WrongContactInResponseTest : public AgentTest {

	void testExec() override {
		// Create a sip response event with transport corresponding to received "ip:port" in the first "VIA" header.
		const string request =
		    "SIP/2.0 200 OK\r\n"
		    "Via: SIP/2.0/TCP sip.example.org;rport;branch=z9hG4bK.0vB2p8BDSm6ajjQQFgQ0t6a20F;received=1.2.3.4\r\n"
		    "Via: SIP/2.0/TLS 10.0.0.8:12345;branch=z9hG4bK.u8Dh~xcjx;rport=6789;received=5.6.7.8\r\n"
		    "Record-Route: <sip:sip.example.org:5060;transport=tcp;lr>\r\n"
		    "Record-Route: <sips:sip.example.org:5061;lr>\r\n"
		    "From: <sip:callee@sip.example.org>;tag=Qx935r3\r\n"
		    "To: \"Caller\" <sip:caller@10.0.1.5>;tag=fd983a4f\r\n"
		    "Contact: <sip:caller@10.0.1.5;transport=tcp>\r\n"
		    "Call-ID: cb30345a285a7608c0a269db7528176e\r\n"
		    "CSeq: 113 INVITE\r\n"
		    "Session-Expires: 1800;refresher=uas\r\n"
		    "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, REFER, SUBSCRIBE, NOTIFY, MESSAGE, INFO, PRACK\r\n"
		    "Allow-Events: presence, refer, dialog\r\n"
		    "Accept: application/sdp\r\n"
		    "Accept-Encoding: identity\r\n"
		    "Accept-Language: en\r\n"
		    "Supported: 100rel, replaces, timer\r\n"
		    "User-Agent: VeriCall Edge\r\n"
		    "Content-Type: application/sdp\r\n"
		    "Content-Length: 261";
		// Create sip message with "ip:port" corresponding to "received" in the first "VIA" header.
		const auto msg = make_shared<MsgSip>(0, request);
		const auto sockAddr = reinterpret_cast<sockaddr_in*>(msg->getSockAddr());
		sockAddr->sin_family = AF_INET;
		sockAddr->sin_addr.s_addr = htonl(0x05060708);
		sockAddr->sin_port = htons(6789);
		// Create dummy incoming transport to make NatHelper::needToBeFixed return true.
		tp_name_t name{"tcp", nullptr, "127.0.0.1", "5060", nullptr, nullptr};
		const auto incomingTport = tport_by_name(nta_agent_tports(mAgent->getSofiaAgent()), &name);
		auto event = make_shared<ResponseSipEvent>(mAgent, msg, incomingTport);

		const auto module = dynamic_pointer_cast<NatHelper>(mAgent->findModule("NatHelper"));
		module->onResponse(event);

		const auto contact = event->getSip()->sip_contact;
		BC_HARD_ASSERT(contact != nullptr);
		const auto url = url_as_string(event->getHome(), contact->m_url);
		BC_ASSERT_STRING_EQUAL(url, "sip:caller@5.6.7.8:6789;transport=tcp");
	}
};

namespace {
TestSuite _("NatHelperModule", {TEST_NO_TAG_AUTO_NAMED(run<WrongContactInResponseTest>)});
}

} // namespace flexisip::tester
