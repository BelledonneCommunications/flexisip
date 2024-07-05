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

#include <chrono>
#include <string>
#include <string_view>

#include "auth-utils.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/proxy-server.hh"
#include "utils/redis-server.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::string_literals;
using namespace sofiasip;
using namespace flexisip;
using namespace flexisip::tester;
using namespace flexisip::tester::authentication;

namespace {
constexpr auto domainA = "a.example.org";
constexpr auto domainB = "b.example.org";
const auto clientA = "sip:user1@"s + domainA;
const auto clientA2 = "sip:user2@"s + domainA;
const auto clientB = "sip:user1@"s + domainB;

Server createServer(string_view domain,
                    string_view filename,
                    const shared_ptr<sofiasip::SuRoot>& root = make_shared<sofiasip::SuRoot>()) {
	return Server(
	    {
	        {"module::Registrar/reg-domains", "*"},
	        {"module::Authentication/enabled", "true"},
	        {"module::Authentication/file-path", filename.data()},
	        {"module::Authentication/auth-domains", domain.data()},
	    },
	    root);
}

void rejectRequest(string_view serverDomain, string_view request, const Response& response) {
	TempFile authFile("version:1\n");
	auto proxy = createServer(serverDomain, authFile.getFilename());
	const auto& root = proxy.getRoot();
	proxy.start();

	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
	checkResponse(transaction, response);
}

// Send a REGISTER request without authentication data for a user on the proxy's domain.
// Expect the proxy to reply 401 unauthorized and provide authentication parameters.
void rejectUnauthRegisterOfAToProxyA() {
	const auto request = registerRequest(clientA, "1");
	rejectRequest(domainA, request, response_401_unauthorized);
}

// Send a REGISTER request without authentication data for a user on another proxy's domain.
// Expect the proxy to reply 403 forbidden.
void rejectUnauthRegisterOfAToProxyB() {
	const auto request = registerRequest(clientA, "1");
	rejectRequest(domainB, request, response_403_forbidden);
}

// Send a REGISTER request without authentication data for a user of proxy's domain but with another outbound proxy.
// Expect the proxy to reply 403 forbidden.
void rejectUnauthRegisterOfAToProxyAViaProxyB() {
	auto root = make_shared<sofiasip::SuRoot>();
	TempFile authFile("version:1\n");
	auto domainAServer = createServer(domainA, authFile.getFilename(), root);
	domainAServer.start();

	auto domainBServer = createServer(domainB, authFile.getFilename(), root);
	domainBServer.start();

	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	const auto routeViaDomainB = "Route: <sip:127.0.0.1:"s + domainBServer.getFirstPort() + ";transport=tcp;lr>\r\n";
	const auto request = registerRequest(clientA, "1", routeViaDomainB);
	const auto transaction = sendRequest(UAClient, root, request, domainBServer.getFirstPort());
	checkResponse(transaction, response_403_forbidden);
}

// Send a MESSAGE without authentication data to a user of domain.
// Expect the proxy to reply 407 unauthorized and provide authentication parameters.
void rejectUnauthMessageOfAToA2() {
	// clang-format off
	string request(
	    "MESSAGE "s + clientA2 + " SIP/2.0\r\n" +
		"Max-Forwards: 5\r\n"
		"To: <" + clientA2 + ">\r\n"
		"From: <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 1 MESSAGE\r\n"
		"Contact: <" + clientA + ";>;+sip.instance=fcm1Reg\r\n"
		"Content-Type: text/plain\r\n"
		"Ce message n'arrivera pas !\r\n");
	// clang-format on

	rejectRequest(domainA, request, response_407_proxy_auth_required);
}

// Send an INVITE without authentication data to a user of domain.
// Expect the proxy to reply 407 unauthorized and provide authentication parameters.
void rejectUnauthInviteOfAToA2() {
	// clang-format off
	string request(
	    "INVITE "s + clientA2 + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientA2 + ">\r\n"
		"From: user1 <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 10 INVITE\r\n"
		"Contact: <" + clientA + ";transport=tcp>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	rejectRequest(domainA, request, response_407_proxy_auth_required);
}

// Send a SUBSCRIBE without authentication data to a user of domain.
// Expect the proxy to reply 407 unauthorized and provide authentication parameters.
void rejectUnauthSubscribeOfAToA2() {
	// clang-format off
	string request(
	    "SUBSCRIBE "s + clientA2 + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientA2 + ">\r\n"
		"From: user1 <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 10 SUBSCRIBE\r\n"
		"Event: presence\r\n"
		"Contact: <" + clientA + ";transport=tcp>\r\n"
		"Expires: 3600\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	rejectRequest(domainA, request, response_407_proxy_auth_required);
}

// Send an OPTIONS without authentication data to a user of domain.
// Expect the proxy to reply 407 unauthorized and provide authentication parameters.
void rejectUnauthOptionsOfAToA2() {
	// clang-format off
	string request(
	    "OPTIONS "s + clientA2 + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientA2 + ">\r\n"
		"From: user1 <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 11 OPTIONS\r\n"
		"Contact: <" + clientA + ";transport=tcp>\r\n"
		"Accept: application/sdp\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	rejectRequest(domainA, request, response_407_proxy_auth_required);
}

// Send a MESSAGE without authentication data to a user of another domain.
// Expect the proxy to reply 403 forbidden.
void rejectUnauthMessageOfAToB() {
	// clang-format off
	string request(
	    "MESSAGE "s + clientB + " SIP/2.0\r\n" +
		"Max-Forwards: 5\r\n"
		"To: <" + clientB + ">\r\n"
		"From: <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 1 MESSAGE\r\n"
		"Contact: <" + clientA + ";>;+sip.instance=fcm1Reg\r\n"
		"Content-Type: text/plain\r\n"
		"Ce message n'arrivera pas !\r\n");
	// clang-format on

	rejectRequest(domainB, request, response_403_forbidden);
}

// Send an INVITE without authentication data to a user of another domain.
// Expect the proxy to reply 403 forbidden.
void rejectUnauthInviteOfAToB() {
	// clang-format off
	string request(
	    "INVITE "s + clientB + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientB + ">\r\n"
		"From: user1 <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 10 INVITE\r\n"
		"Contact: <" + clientA + ";transport=tcp>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	rejectRequest(domainB, request, response_403_forbidden);
}

// Send a SUBSCRIBE without authentication data to a user of another domain.
// Expect the proxy to reply 403 forbidden.
void rejectUnauthSubscribeOfAToB() {
	// clang-format off
	string request(
	    "SUBSCRIBE "s + clientB + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientB + ">\r\n"
		"From: user1 <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 10 SUBSCRIBE\r\n"
		"Event: presence\r\n"
		"Contact: <" + clientA + ";transport=tcp>\r\n"
		"Expires: 3600\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	rejectRequest(domainB, request, response_403_forbidden);
}

// Send an OPTIONS without authentication data to a user of another domain.
// Expect the proxy to reply 403 forbidden.
void rejectUnauthOptionsOfAToB() {
	// clang-format off
	string request(
	    "OPTIONS "s + clientB + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientB + ">\r\n"
		"From: user1 <" + clientA + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: 11 OPTIONS\r\n"
		"Contact: <" + clientA + ";transport=tcp>\r\n"
		"Accept: application/sdp\r\n"
		"Content-Length: 0\r\n");
	// clang-format on

	rejectRequest(domainB, request, response_403_forbidden);
}

TestSuite _("AuthDomains",
            {
                CLASSY_TEST(rejectUnauthRegisterOfAToProxyA),
                CLASSY_TEST(rejectUnauthRegisterOfAToProxyB),
                CLASSY_TEST(rejectUnauthRegisterOfAToProxyAViaProxyB),
                CLASSY_TEST(rejectUnauthMessageOfAToA2),
                CLASSY_TEST(rejectUnauthInviteOfAToA2),
                CLASSY_TEST(rejectUnauthSubscribeOfAToA2),
                CLASSY_TEST(rejectUnauthOptionsOfAToA2),
                CLASSY_TEST(rejectUnauthMessageOfAToB),
                CLASSY_TEST(rejectUnauthInviteOfAToB),
                CLASSY_TEST(rejectUnauthSubscribeOfAToB),
                CLASSY_TEST(rejectUnauthOptionsOfAToB),
            });
} // namespace