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

#include <string>
#include <string_view>

#include <jwt/jwt.hpp>

#include "auth-utils.hh"
#include "rsa-keys.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/proxy-server.hh"
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
const string userName = "alphonse";
const auto contact = userName + "@" + domainA;
const auto sipUri = "sip:"s + contact;
constexpr auto domainB = "b.example.org";
string clientB = "sip:TeddyBear"s + "@" + domainB;

string readParamValue(const msg_param_t* msgParams, const char* field) {
	auto fieldValue = msg_params_find(msgParams, field);
	string value(fieldValue ? fieldValue : "");
	if (value.find_first_of("\"") != 0) return value;

	// quoted string
	unsigned int quoteSize = 2;
	if (value.size() < quoteSize) return string{};
	// remove quote
	return value.substr(1, value.size() - quoteSize);
}

string generateToken(string_view issuer, string_view sipUri) {
	jwt::jwt_object obj{jwt::params::algorithm("RS256"), jwt::params::secret(kRsaPrivKey)};
	obj.add_claim("iss", issuer.data());
	obj.add_claim("sub", "testSubject");
	obj.add_claim("aud", "test");
	obj.add_claim("sip_identity", sipUri);
	obj.add_claim("iat", chrono::system_clock::now());
	obj.add_claim("exp", chrono::system_clock::now() + 60s);
	return obj.signature();
}

void rejectUnauthReq() {
	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::AuthOpenIDConnect/enabled", "true"},
	              {"module::AuthOpenIDConnect/authorization-server", "HtTPS://toto.example.org"},
	              {"module::AuthOpenIDConnect/realm", "example.org"},
	              {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	              {"module::Authorization/enabled", "true"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:localhost:0");

	{
		// first REGISTER request is rejected, server reply with authentication parameters
		const auto request = registerRequest(sipUri, "1");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_401_unauthorized);
	}
	{
		// clang-format off
		string request(
		    "MESSAGE "s + clientB + " SIP/2.0\r\n" +
			"Max-Forwards: 5\r\n"
			"To: <" + clientB + ">\r\n"
			"From: <" + sipUri + ">;tag=465687829\r\n"
			"Call-ID: 1053183492\r\n"
			"CSeq: 1 MESSAGE\r\n"
			"Contact: <" + sipUri + ";>;+sip.instance=fcm1Reg\r\n"
			"Content-Type: text/plain\r\n"
			"Ce message n'arrivera pas !\r\n");
		// clang-format on

		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_407_proxy_auth_required);
	}
}

void bearerAuth() {
	TempFile keyFile(kRsaPubKey);
	const auto issuer = "https://example.org";
	const auto realm = "testRealm";

	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::AuthOpenIDConnect/enabled", "true"},
	              {"module::AuthOpenIDConnect/authorization-server", issuer},
	              {"module::AuthOpenIDConnect/realm", realm},
	              {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	              {"module::AuthOpenIDConnect/public-key-type", "file"},
	              {"module::AuthOpenIDConnect/public-key-location", keyFile.getFilename()},
	              {"module::Authorization/enabled", "true"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:localhost:0");

	{
		// first REGISTER request is rejected, server reply with authentication parameters
		const auto request = registerRequest(sipUri, "1");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_401_unauthorized);

		const auto* sipMsg = transaction->getResponse()->getSip();
		BC_HARD_ASSERT(sipMsg != nullptr);
		const auto* authMsg = sipMsg->sip_www_authenticate;
		BC_HARD_ASSERT(authMsg != nullptr);
		const auto* authParams = authMsg->au_params;
		BC_HARD_ASSERT(authParams != nullptr);
		BC_ASSERT_CPP_EQUAL(readParamValue(authParams, "authz_server"), issuer);
		BC_ASSERT_CPP_EQUAL(readParamValue(authParams, "realm"), realm);
	}

	// generate a valid authorization
	const auto token = generateToken(issuer, sipUri);
	const auto authorization = string("Authorization: Bearer "s + token + "\r\n");

	// REGISTER with a valid token but a different from sip uri
	{
		const auto anotherSipUri = "sip:"s + userName + "@" + realm;
		const auto request = registerRequest(anotherSipUri, "2", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_401_unauthorized);
	}

	// REGISTER with a valid Authorization header
	{
		const auto request = registerRequest(sipUri, "2", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}
}

// Send an authenticate message to a client of another proxy
// Expect success and that Proxy A removes its creadentials before forwarding message to B
void bearerMsgOfAToB() {
	constexpr auto issuerA = "https://a.example.org";
	constexpr auto issuerB = "https://b.example.org";
	constexpr auto realm = "testRealm";
	TempFile keyFile(kRsaPubKey);

	// add an entry module that check a proxy remove its credentials
	// the module registration is static, adding it to the 1st proxy will adding it to both
	auto expectedProxyAuth = 2;
	InjectedHooks hooks{
	    .onRequest =
	        [&expectedProxyAuth](const std::shared_ptr<RequestSipEvent>& responseEvent) {
		        auto numProxyAuth = 0;
		        const auto* sip = responseEvent->getSip();
		        auto* credentials = sip->sip_proxy_authorization;
		        while (credentials != nullptr) {
			        ++numProxyAuth;
			        credentials = credentials->au_next;
		        }
		        BC_ASSERT_CPP_EQUAL(numProxyAuth, expectedProxyAuth);
		        --expectedProxyAuth;
	        },
	};

	auto root = make_shared<sofiasip::SuRoot>();

	// register clientB contact address
	TempFile regFileB("<" + clientB + "> <sip:127.0.0.1:5460>");
	Server proxyB({{"module::Registrar/reg-domains", domainB},
	               {"module::Registrar/static-records-file", regFileB.getFilename()},
	               {"module::AuthOpenIDConnect/enabled", "true"},
	               {"module::AuthOpenIDConnect/authorization-server", issuerB},
	               {"module::AuthOpenIDConnect/realm", realm},
	               {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	               {"module::AuthOpenIDConnect/public-key-type", "file"},
	               {"module::AuthOpenIDConnect/public-key-location", keyFile.getFilename()},
	               {"module::Authorization/enabled", "true"}},
	              root, &hooks);
	proxyB.start();
	SLOGD << "Start ProxyB with port: " << proxyB.getFirstPort();

	// register clientB contact address to proxyB
	TempFile regFileA("<" + clientB + "> <sip:127.0.0.1:" + proxyB.getFirstPort() + ">");

	Server proxyA({{"module::Registrar/reg-domains", domainA},
	               {"module::Registrar/static-records-file", regFileA.getFilename()},
	               {"module::AuthOpenIDConnect/enabled", "true"},
	               {"module::AuthOpenIDConnect/authorization-server", issuerA},
	               {"module::AuthOpenIDConnect/realm", realm},
	               {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	               {"module::AuthOpenIDConnect/public-key-type", "file"},
	               {"module::AuthOpenIDConnect/public-key-location", keyFile.getFilename()},
	               {"module::Authorization/enabled", "true"}},
	              root);

	proxyA.start();
	SLOGD << "Start ProxyA with port: " << proxyA.getFirstPort();

	// add Route to bypass domain name resolution
	const auto routeDomainB = "Route: <sip:127.0.0.1:"s + proxyB.getFirstPort() + ";transport=tcp;lr>\r\n";
	const auto routeDomainA = "Route: <sip:127.0.0.1:"s + proxyA.getFirstPort() + ";transport=tcp;lr>\r\n";
	// generate a valid authorization for each Proxy
	const auto authorizationA = "Proxy-Authorization: Bearer "s + generateToken(issuerA, sipUri) + "\r\n";
	const auto authorizationB = "Proxy-Authorization: Bearer "s + generateToken(issuerB, sipUri) + "\r\n";

	// clang-format off
		string request(
		    "MESSAGE "s + clientB + " SIP/2.0\r\n" +
			"Max-Forwards: 5\r\n"
			"To: <" + clientB + ">\r\n"
			"From: <" + sipUri + ">;tag=465687829\r\n"
			"Call-ID: 1053183492\r\n"
			"CSeq: 1 MESSAGE\r\n"
			"Contact: <" + sipUri + ";>;+sip.instance=fcm1Reg\r\n"
			+ routeDomainA.c_str() +
			+ routeDomainB.c_str() +
			+ authorizationB.c_str() +
			+ authorizationA.c_str() +
			"Content-Type: text/plain\r\n"
			"Ce message n'arrivera pas !\r\n");
	// clang-format on

	auto readMsgCounter = [](Server& proxy) {
		auto* global = proxy.getConfigManager()->getRoot()->get<GenericStruct>("global");
		return global->getStat("count-incoming-request-message")->read();
	};

	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyA), 0);
	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyB), 0);

	NtaAgent UAClient(root, "sip:localhost:0");
	const auto transaction = sendRequest(UAClient, root, request, proxyA.getFirstPort());
	// ensure each proxy received a message
	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyA), 1);
	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyB), 1);

	// expect success
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 202);
	BC_ASSERT_CPP_EQUAL(expectedProxyAuth, 0);
}

TestSuite _("AuthOpenIDConnect",
            {
                CLASSY_TEST(rejectUnauthReq),
                CLASSY_TEST(bearerAuth),
                CLASSY_TEST(bearerMsgOfAToB),
            });
} // namespace