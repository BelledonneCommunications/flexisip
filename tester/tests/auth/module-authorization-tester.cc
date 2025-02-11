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
#include <fstream>

#include "module-authorization.hh"

#include "auth-utils.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
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

// Check that a request is rejected with 403 if its domain is not specified
void rejectUnexpectedDomain() {
	Server proxy({
	    {"module::Registrar/reg-domains", "*.example.org"},
	    {"module::Authorization/enabled", "true"},
	    {"module::Authorization/auth-domains", ""},
	});

	proxy.start();
	const auto root = proxy.getRoot();

	const auto request = registerRequest(clientA, "1");
	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
	checkResponse(transaction, response_403_forbidden);
}

// Check that a trusted host request is accepted even if its domain is not specified
void acceptTrustedHostOfUnexpectedDomain() {
	InjectedHooks forceTrustedHost{
	    .onRequest =
	        [](unique_ptr<RequestSipEvent>&& ev) {
		        ev->setTrustedHost();
		        return std::move(ev);
	        },
	};

	Server proxy(
	    {
	        {"module::Registrar/reg-domains", "*.example.org"},
	        {"module::Authorization/enabled", "true"},
	        {"module::Authorization/auth-domains", ""},
	    },
	    &forceTrustedHost);

	proxy.start();
	const auto root = proxy.getRoot();

	const auto request = registerRequest(clientA, "1");
	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
	checkResponse(transaction, response_200_ok);
}

// Check that an unauthenticated request of a valid domain is rejected with 401 for REGISTER and 407 otherwise
void rejectUnauthUserOfValidDomain() {
	Server proxy({
	    {"module::Registrar/reg-domains", "*.example.org"},
	    {"module::Authorization/enabled", "true"},
	    {"module::Authorization/auth-domains", domainA},
	});
	proxy.start();
	const auto root = proxy.getRoot();

	struct ChallengerMock : public AuthScheme {
		std::string schemeType() const {
			return "ChallengerMock";
		}
		void challenge(AuthStatus&, const auth_challenger_t*) {
		}
		State check(const msg_auth_t*, std::function<void(ChallengeResult&&)>&&) {
			return State::Done;
		}
	};
	auto authModule = proxy.getAgent()->findModule("Authorization");
	auto auth = dynamic_cast<ModuleAuthorization*>(authModule.get());
	auth->addAuthModule(make_shared<ChallengerMock>());

	{
		const auto request = registerRequest(clientA, "1");
		NtaAgent UAClient(root, "sip:127.0.0.1:0");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, {SIP_401_UNAUTHORIZED});
	}

	{
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

		NtaAgent UAClient(root, "sip:127.0.0.1:0");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, {SIP_407_PROXY_AUTH_REQUIRED});
	}
}

// Check that a request with a valid challenge and a valid domain is accepted
void acceptAuthUserOfValidDomain() {
	InjectedHooks hooks{
	    .onRequest =
	        [](unique_ptr<RequestSipEvent>&& ev) {
		        // add an invalid challenge result
		        {
			        RequestSipEvent::AuthResult::ChallengeResult chal(RequestSipEvent::AuthResult::Type::Digest);
			        ev->addChallengeResult(std::move(chal));
		        }
		        // add a valid challenge result
		        // request shall be accepted
		        {
			        RequestSipEvent::AuthResult::ChallengeResult chal(RequestSipEvent::AuthResult::Type::Bearer);
			        chal.setIdentity(SipUri(clientA));
			        chal.accept();
			        ev->addChallengeResult(std::move(chal));
		        }
		        return std::move(ev);
	        },
	};
	Server proxy(
	    {
	        {"module::Registrar/reg-domains", "*.example.org"},
	        {"module::Authorization/enabled", "true"},
	        {"module::Authorization/auth-domains", string(domainB) + " " + domainA},
	    },
	    &hooks);

	proxy.start();
	const auto root = proxy.getRoot();
	const auto request = registerRequest(clientA, "1");
	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
	checkResponse(transaction, response_200_ok);
}

// Check that an authenticated request betwen two valid domains is rejected with 403
void rejectInterDomainRequest() {
	InjectedHooks addValidChallengeResult{
	    .onRequest =
	        [](unique_ptr<RequestSipEvent>&& ev) {
		        RequestSipEvent::AuthResult::ChallengeResult chal(RequestSipEvent::AuthResult::Type::Bearer);
		        chal.setIdentity(SipUri(ev->getSip()->sip_from->a_url));
		        chal.accept();
		        ev->addChallengeResult(std::move(chal));
		        return std::move(ev);
	        },
	};

	Server proxy(
	    {
	        {"module::Registrar/reg-domains", "*.example.org"},
	        {"module::Authorization/enabled", "true"},
	        {"module::Authorization/auth-domains", string(domainB) + " " + domainA},
	    },
	    &addValidChallengeResult);

	proxy.start();
	const auto root = proxy.getRoot();

	// accept request from A
	{
		const auto request = registerRequest(clientA, "1");
		NtaAgent UAClient(root, "sip:127.0.0.1:0");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}

	// accept request from B
	{
		const auto request = registerRequest(clientB, "1");
		NtaAgent UAClient(root, "sip:127.0.0.1:0");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}

	// but reject request from A to B
	{
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

		NtaAgent UAClient(root, "sip:127.0.0.1:0");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_403_forbidden);
	}
}

const TestSuite kSuite{"Authorization",
                       {
                           CLASSY_TEST(rejectUnexpectedDomain),
                           CLASSY_TEST(acceptTrustedHostOfUnexpectedDomain),
                           CLASSY_TEST(rejectUnauthUserOfValidDomain),
                           CLASSY_TEST(acceptAuthUserOfValidDomain),
                           CLASSY_TEST(rejectInterDomainRequest),
                       }};
} // namespace