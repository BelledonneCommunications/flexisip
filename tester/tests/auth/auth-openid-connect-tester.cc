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
#include <string>
#include <string_view>

#include <jwt/jwt.hpp>

#include "auth-utils.hh"
#include "rsa-keys.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace std::string_literals;
using namespace sofiasip;
using namespace flexisip;
using namespace flexisip::tester;
using namespace flexisip::tester::authentication;

namespace {
constexpr auto domainA = "a.example.org";
constexpr auto audienceA = "testDomainA";
const string userName = "alphonse";
const auto contact = userName + "@" + domainA;
const auto sipUri = "sip:"s + contact;
constexpr auto domainB = "b.example.org";
constexpr auto audienceB = "testDomainB";
string clientB = "sip:TeddyBear"s + "@" + domainB;

struct SuiteScope {
	TmpDir dir;
	filesystem::path rsaPubKey;
};

auto sSuiteScope = std::optional<SuiteScope>();

string readParamValue(const msg_param_t* msgParams, const char* field) {
	auto fieldValue = msg_params_find(msgParams, field);
	string value(fieldValue ? fieldValue : "");
	if (value.find_first_of('"') != 0) return value;

	// quoted string
	unsigned int quoteSize = 2;
	if (value.size() < quoteSize) return string{};
	// remove quote
	return value.substr(1, value.size() - quoteSize);
}

string generateToken(string_view issuer, string_view sipUri, string_view kid, string_view aud) {
	jwt::jwt_object obj{jwt::params::algorithm("RS256"), jwt::params::secret(kRsaPrivKey)};
	obj.header().add_header("kid", kid);
	obj.add_claim("iss", issuer);
	obj.add_claim("sub", "testSubject");
	obj.add_claim("aud", aud);
	obj.add_claim("sip_identity", sipUri);
	obj.add_claim("iat", chrono::system_clock::now());
	obj.add_claim("exp", chrono::system_clock::now() + 60s);
	return obj.signature();
}

// Check that an authenticated request is rejected
void rejectUnauthReq() {
	Server proxy({
	    {"module::Registrar/reg-domains", "*"},
	    {"module::AuthOpenIDConnect/enabled", "true"},
	    {"module::AuthOpenIDConnect/authorization-server", "HtTPS://toto.example.org"},
	    {"module::AuthOpenIDConnect/realm", "example.org"},
	    {"module::AuthOpenIDConnect/audience", "test"},
	    {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	    {"module::AuthOpenIDConnect/public-key-type", "file"},
	    {"module::AuthOpenIDConnect/public-key-location", sSuiteScope->rsaPubKey},
	    {"module::Authorization/enabled", "true"},
	    {"module::Authorization/auth-domains", domainA},
	});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	{
		// first REGISTER request is rejected, server reply with authentication parameters
		const auto request = registerRequest(sipUri, "1");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_401_unauthorized);
	}
	{
		const auto clientA = "sip:myfriend@"s + domainA;
		// clang-format off
		string request(
		    "MESSAGE "s + clientA+ " SIP/2.0\r\n" +
			"Max-Forwards: 5\r\n"
			"To: <" + clientA + ">\r\n"
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

// Check that an authorization header that is not for the module doesn't cause an issue
void rejectDigestAuthReq() {
	const auto issuer = "https://example.org";
	const auto realm = "testRealm";

	Server proxy({
	    {"module::Registrar/reg-domains", "*"},
	    {"module::AuthOpenIDConnect/enabled", "true"},
	    {"module::AuthOpenIDConnect/authorization-server", issuer},
	    {"module::AuthOpenIDConnect/realm", realm},
	    {"module::AuthOpenIDConnect/audience", audienceA},
	    {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	    {"module::AuthOpenIDConnect/public-key-type", "file"},
	    {"module::AuthOpenIDConnect/public-key-location", sSuiteScope->rsaPubKey},
	    {"module::Authorization/enabled", "true"},
	    {"module::Authorization/auth-domains", domainA},
	});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	// clang-format off
	string authorization(
		"Authorization: Digest username=\""s + userName + "\","
			" realm=\"" + realm + "\","
			" nonce=\"fake-nonce\","
			" uri="+ sipUri + ","
			" response=\"b3bbfb167db5b34da8285546af976a10\","
			" algorithm=MD5,"
			" opaque=\"fake-opaque\"\r\n");
	// clang-format on
	const auto request = registerRequest(sipUri, "1", authorization);
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
	checkResponse(transaction, response_401_unauthorized);
}

/**
 * Check complete Bearer authentication process:
 * - the server replies with authentication parameters to an unauthenticated request
 * - the server accepts a valid token with the appropriate sip-identity
 */
void bearerAuth() {
	const auto issuer = "https://example.org";
	const auto realm = "testRealm";

	Server proxy({
	    {"module::Registrar/reg-domains", "*"},
	    {"module::AuthOpenIDConnect/enabled", "true"},
	    {"module::AuthOpenIDConnect/authorization-server", issuer},
	    {"module::AuthOpenIDConnect/realm", realm},
	    {"module::AuthOpenIDConnect/audience", audienceA},
	    {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	    {"module::AuthOpenIDConnect/public-key-type", "file"},
	    {"module::AuthOpenIDConnect/public-key-location", sSuiteScope->rsaPubKey},
	    {"module::Authorization/enabled", "true"},
	    {"module::Authorization/auth-domains", domainA},
	});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

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
	const auto token = generateToken(issuer, sipUri, "default", audienceA);
	const auto authorization = string("Authorization: Bearer "s + token + "\r\n");

	// REGISTER with a valid token but a different from sip uri
	{
		const auto anotherSipUri = "sip:another@"s + domainA;
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

	// add an entry module that check a proxy remove its credentials
	// the module registration is static, adding it to the 1st proxy will adding it to both
	auto expectedProxyAuth = 2;
	InjectedHooks hooks{
	    .onRequest =
	        [&expectedProxyAuth](std::unique_ptr<RequestSipEvent>&& requestEvent) {
		        auto numProxyAuth = 0;
		        const auto* sip = requestEvent->getSip();
		        auto* credentials = sip->sip_proxy_authorization;
		        while (credentials != nullptr) {
			        ++numProxyAuth;
			        credentials = credentials->au_next;
		        }
		        BC_ASSERT_CPP_EQUAL(numProxyAuth, expectedProxyAuth);
		        --expectedProxyAuth;
		        return std::move(requestEvent);
	        },
	};

	auto root = make_shared<sofiasip::SuRoot>();

	// register clientB contact address
	const auto& regFileB = sSuiteScope->dir.path() / "regFileB";
	ofstream(regFileB) << "<" << clientB << "> <sip:127.0.0.1:5460>";
	Server proxyB(
	    {
	        {"module::Registrar/reg-domains", domainB},
	        {"module::Registrar/static-records-file", regFileB},
	        {"module::AuthOpenIDConnect/enabled", "true"},
	        {"module::AuthOpenIDConnect/authorization-server", issuerB},
	        {"module::AuthOpenIDConnect/realm", realm},
	        {"module::AuthOpenIDConnect/audience", audienceB},
	        {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	        {"module::AuthOpenIDConnect/public-key-type", "file"},
	        {"module::AuthOpenIDConnect/public-key-location", sSuiteScope->rsaPubKey},
	        {"module::Authorization/enabled", "true"},
	        {"module::Authorization/auth-domains", string(domainA) + " " + domainB},
	        // bypass forbidden inter domain request
	        {"module::Authorization/filter", "!from.uri.domain contains '"s + domainA + "'"},
	    },
	    root, &hooks);
	proxyB.start();
	SLOGD << "Start ProxyB with port: " << proxyB.getFirstPort();

	// register clientB contact address to proxyB
	const auto& regFileA = sSuiteScope->dir.path() / "regFileA";
	ofstream(regFileA) << "<" << clientB << "> <sip:127.0.0.1::" << proxyB.getFirstPort() << ">";

	Server proxyA(
	    {
	        {"module::Registrar/reg-domains", domainA},
	        {"module::Registrar/static-records-file", regFileA},
	        {"module::AuthOpenIDConnect/enabled", "true"},
	        {"module::AuthOpenIDConnect/authorization-server", issuerA},
	        {"module::AuthOpenIDConnect/realm", realm},
	        {"module::AuthOpenIDConnect/audience", audienceA},
	        {"module::AuthOpenIDConnect/sip-id-claim", "sip_identity"},
	        {"module::AuthOpenIDConnect/public-key-type", "file"},
	        {"module::AuthOpenIDConnect/public-key-location", sSuiteScope->rsaPubKey},
	        {"module::Authorization/enabled", "true"},
	        {"module::Authorization/auth-domains", domainA},
	        // bypass forbidden inter domain request
	        {"module::Authorization/filter", "!from.uri.domain contains '"s + domainA + "'"},
	    },
	    root);

	proxyA.start();
	SLOGD << "Start ProxyA with port: " << proxyA.getFirstPort();

	// add Route to bypass domain name resolution
	const auto routeDomainB = "Route: <sip:127.0.0.1:"s + proxyB.getFirstPort() + ";transport=tcp;lr>\r\n";
	const auto routeDomainA = "Route: <sip:127.0.0.1:"s + proxyA.getFirstPort() + ";transport=tcp;lr>\r\n";
	// generate a valid authorization for each Proxy
	const auto authorizationA =
	    "Proxy-Authorization: Bearer "s + generateToken(issuerA, sipUri, "default", audienceA) + "\r\n";
	const auto authorizationB =
	    "Proxy-Authorization: Bearer "s + generateToken(issuerB, sipUri, "default", audienceB) + "\r\n";

	// clang-format off
		string request(
		    "MESSAGE "s + clientB + " SIP/2.0\r\n" +
			"Max-Forwards: 5\r\n"
			"To: <" + clientB + ">\r\n"
			"From: <" + sipUri + ">;tag=465687829\r\n"
			"Call-ID: 1053183492\r\n"
			"CSeq: 1 MESSAGE\r\n"
			"Contact: <" + sipUri + ";>;+sip.instance=fcm1Reg\r\n"
			+ routeDomainA
			+ routeDomainB
			+ authorizationB
			+ authorizationA +
			"Content-Type: text/plain\r\n"
			"Ce message n'arrivera pas !\r\n");
	// clang-format on

	auto readMsgCounter = [](Server& proxy) {
		auto* global = proxy.getConfigManager()->getRoot()->get<GenericStruct>("global");
		return global->getStat("count-incoming-request-message")->read();
	};

	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyA), 0);
	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyB), 0);

	NtaAgent UAClient(root, "sip:127.0.0.1:0");
	const auto transaction = sendRequest(UAClient, root, request, proxyA.getFirstPort());
	// ensure each proxy received a message
	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyA), 1);
	BC_ASSERT_CPP_EQUAL(readMsgCounter(proxyB), 1);

	// expect success
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 202);
	BC_ASSERT_CPP_EQUAL(expectedProxyAuth, 0);
}

/**
 * SIP RFC: https://datatracker.ietf.org/doc/html/rfc3261#section-22
 * HTTP RFC: https://datatracker.ietf.org/doc/html/rfc2617
 */
const TestSuite kSuite{
    "AuthOpenIDConnect",
    {
        CLASSY_TEST(rejectUnauthReq),
        CLASSY_TEST(rejectDigestAuthReq),
        CLASSY_TEST(bearerAuth),
        CLASSY_TEST(bearerMsgOfAToB),
    },
    Hooks()
        .beforeSuite([]() {
	        auto dir = TmpDir(kSuite.getName());
	        auto rsaPubKeyPath = dir.path() / "keyFile";
	        ofstream(rsaPubKeyPath) << kRsaPubKey;
	        sSuiteScope.emplace(SuiteScope{
	            .dir = std::move(dir),
	            .rsaPubKey = std::move(rsaPubKeyPath),
	        });
	        return 0;
        })
        .afterSuite([]() {
	        sSuiteScope.reset();
	        return 0;
        }),
};
} // namespace