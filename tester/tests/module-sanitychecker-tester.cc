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

#include <memory>
#include <string>

#include "bctoolbox/tester.h"
#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "module-sanitychecker.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {

int sendRequest(const Server& proxyServer, NtaAgent& client, unique_ptr<MsgSip> msg) {
	auto transaction = client.createOutgoingTransaction(std::move(msg), "sip:127.0.0.1:"s + proxyServer.getFirstPort());
	CoreAssert{proxyServer}.iterateUpTo(5, [&transaction] { return transaction->isCompleted(); }, 1s).assert_passed();
	return transaction->getStatus();
}

/*
 * Check that SanityChecker stops an invalid request and leads to a 400 - Bad request reply.
 */
void stopWithError400AtRequestWithInvalidScheme() {
	bool requestIsValid;
	// Inject custom module to test if the SanityChecker module validated the REGISTER request.
	auto hooks = InjectedHooks{
	    .injectAfterModule = "SanityChecker",
	    .onRequest =
	        [&](auto&& request) {
		        if (!requestIsValid) {
			        BC_FAIL("SanityChecker module shloud stop on invalid request");
		        }
		        return std::move(request);
	        },
	};
	Server proxyServer(
	    {
	        {"global/transports", "sip:127.0.0.1:0"},
	        {"global/aliases", "127.0.0.1"},
	        {"module::DoSProtection/enabled", "false"},
	    },
	    &hooks);
	proxyServer.start();
	NtaAgent client{proxyServer.getRoot(), "sip:127.0.0.1:0"};
	{
		requestIsValid = true;
		// Valid request
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_register, "sip:user@sip.example.org");
		request->makeAndInsert<SipHeaderContact>("<sip:user@sip.example.org>;+sip.instance=fcm1Reg");
		request->makeAndInsert<SipHeaderFrom>("<sip:user@sip.example.org>", "58c85036e4f35fa8");
		request->makeAndInsert<SipHeaderTo>("<sip:user@sip.example.org>");
		request->makeAndInsert<SipHeaderCallID>("stub-call-id");
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_register);
		request->makeAndInsert<SipHeaderExpires>(3600);
		BC_ASSERT_CPP_EQUAL(sendRequest(proxyServer, client, std::move(request)), 200);
	}
	{
		// Invalid scheme in Contact header
		requestIsValid = false;
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_register, "sip:user@sip.example.org");
		request->makeAndInsert<SipHeaderContact>("<user@sip.example123.org>");
		request->makeAndInsert<SipHeaderFrom>("<sip:user@sip.example.org>", "58c85036e4f35fa8");
		request->makeAndInsert<SipHeaderTo>("<sip:user@sip.example.org>");
		request->makeAndInsert<SipHeaderCallID>("stub-call-id");
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_register);
		request->makeAndInsert<SipHeaderExpires>(3600);
		BC_ASSERT_CPP_EQUAL(sendRequest(proxyServer, client, std::move(request)), 400);
	}
}

/*
 * Check that a request with an invalid header is detected and that an InvalidRequestError exception is thrown.
 */
void reply400ToInvalidRequest() {

	Server proxyServer({
	    {"global/transports", "sip:127.0.0.1:0"},
	    {"global/aliases", "127.0.0.1"},
	    {"module::DoSProtection/enabled", "false"},
	});
	proxyServer.start();
	const auto& sanityCheckerModule =
	    static_pointer_cast<ModuleSanityChecker>(proxyServer.getAgent()->findModuleByRole("SanityChecker"));
	BC_HARD_ASSERT(sanityCheckerModule != nullptr);

	// Valid URI in request
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_FALSE(sanityCheckerModule->processRequest(std::move(event))->isTerminated());
	}
	// No via
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Invalid scheme in contact header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <user@sip.example.org>\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Invalid contact header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		event->getSip()->sip_contact->m_url->url_host = nullptr;
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Invalid URI in to header: forbidden `@` in host part
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:test@user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing host part in to header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		event->getSip()->sip_to->a_url->url_host = nullptr;
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing to header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Invalid URI in From header : forbidden `\\` in host part
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.ex\\ample.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing host part in from header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		event->getSip()->sip_from->a_url->url_host = nullptr;
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing from header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing tag in from header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:test@sip.example.org>\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing request header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		event->getSip()->sip_request = nullptr;
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing host part in request header
	{
		stringstream request;
		request << "REGISTER sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: <sip:user@sip.example.org>\r\n"
		        << "Call-ID: c82d26f4-6654-123f-3e87@stub-call-id\r\n"
		        << "CSeq: 20 REGISTER\r\n"
		        << "Contact: <sip:user@sip.example.org>;+sip.instance=fcm1Reg\r\n"
		        << "Expires: 3600\r\n"
		        << "Content-Length: 0\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		event->getSip()->sip_request->rq_url->url_host = nullptr;
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
	// Missing event header in Subscribe request
	{
		stringstream request;
		request << "SUBSCRIBE sip:user@sip.example.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.4\r\n"
		        << "From: <sip:user@sip.example.org>;tag=58c85036e4f35fa8\r\n"
		        << "To: sips:user@sip.example.org\r\n"
		        << "CSeq: 20 SUBSCRIBE\r\n"
		        << "Content-Length: 0\r\n\r\n";
		auto event =
		    make_unique<RequestSipEvent>(proxyServer.getAgent(), make_shared<MsgSip>(0, request.str()), nullptr);
		BC_ASSERT_THROWN(sanityCheckerModule->onRequest(std::move(event)), InvalidRequestError);
	}
}

TestSuite _("SanityCheckerModule",
            {
                CLASSY_TEST(stopWithError400AtRequestWithInvalidScheme),
                CLASSY_TEST(reply400ToInvalidRequest),
            });

} // namespace

} // namespace flexisip::tester