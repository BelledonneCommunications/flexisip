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

#include "module-router-message-shared-tests.hh"

#include <memory>

#include "conference/chatroom-prefix.hh"
#include "flexisip/module-router.hh"
#include "utils/asserts.hh"
#include "utils/bellesip-utils.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester::router {

void sipMessageRequestIntendedForChatroom(bool messageDatabaseEnabled, const string& connectionString) {
	Server proxy{{
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Router/message-fork-late", "true"},
	    {"module::Router/message-database-enabled", messageDatabaseEnabled ? "true" : "false"},
	    {"module::Router/message-database-connection-string", connectionString},
	}};
	proxy.start();

	const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	auto isRequestReceived = false;
	BellesipUtils senderClient{
	    "127.0.0.1",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&isRequestReceived](int status) {
		    if (status != 100) {
			    BC_HARD_ASSERT_CPP_EQUAL(status, 200);
			    isRequestReceived = true;
		    }
	    },
	};

	ClientBuilder builder{*proxy.getAgent()};
	auto oldSdkReceiver = builder.build("sip:chatroom-old-sdk@sip.example.org");
	auto newSdkReceiver = builder.build("sip:chatroomNewSdk@sip.example.org");
	CoreAssert asserter{proxy, senderClient, oldSdkReceiver, newSdkReceiver};

	// Test for Flexisip-conference with SDK < 5.4
	{
		stringstream request{};
		string body{"This is a test message.\r\n\r\n"};
		const auto gr = "urn:uuid:"s + oldSdkReceiver.getUuid();
		request << "MESSAGE sip:chatroom-old-sdk@sip.example.org;gr=" << gr << " SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:1234;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
		        << "From: <sip:sender@sip.example.org>;tag=stub-from-tag\r\n"
		        << "To: <sip:chatroom-old-sdk@sip.example.org;gr=" << gr << ">\r\n"
		        << "CSeq: 20 MESSAGE\r\n"
		        << "Call-ID: stub-call-id" << "\r\n"
		        << "Max-Forwards: 70\r\n"
		        << "Route: <sip:127.0.0.1:" << proxy.getFirstPort() << ";transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu\r\n"
		        << "Content-Type: text/plain\r\n"
		        << "Content-Length: " << body.size() << "\r\n\r\n";
		senderClient.sendRawRequest(request.str(), body);

		asserter.iterateUpTo(128, [&] { return LOOP_ASSERTION(isRequestReceived == true); }, 2s).hard_assert_passed();

		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->finish->read(), 1);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->start->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->finish->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->start->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->finish->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->start->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageConferenceForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageConferenceForks->finish->read(), 1);
	}

	isRequestReceived = false;

	// Test for Flexisip-conference with SDK >= 5.4
	{
		stringstream request{};
		string body{"This is a test message.\r\n\r\n"};
		request << "MESSAGE sip:chatroomNewSdk@sip.example.org;" << conference::CONFERENCE_ID << "=stubid SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:1234;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
		        << "From: <sip:sender@sip.example.org>;tag=stub-from-tag\r\n"
		        << "To: <sip:chatroomNewSdk@sip.example.org;" << conference::CONFERENCE_ID << "=stubid>\r\n"
		        << "CSeq: 20 MESSAGE\r\n"
		        << "Call-ID: stub-call-id" << "\r\n"
		        << "Max-Forwards: 70\r\n"
		        << "Route: <sip:127.0.0.1:" << proxy.getFirstPort() << ";transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu\r\n"
		        << "Content-Type: text/plain\r\n"
		        << "Content-Length: " << body.size() << "\r\n\r\n";
		senderClient.sendRawRequest(request.str(), body);

		asserter.iterateUpTo(128, [&] { return LOOP_ASSERTION(isRequestReceived == true); }, 2s).hard_assert_passed();

		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->start->read(), 2);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->finish->read(), 2);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->start->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->finish->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->start->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->finish->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->start->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageConferenceForks->start->read(), 2);
		BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageConferenceForks->finish->read(), 2);
	}
}

} // namespace flexisip::tester::router