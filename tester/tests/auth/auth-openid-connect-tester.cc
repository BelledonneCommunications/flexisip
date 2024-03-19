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
constexpr auto domain = "a.example.org";
const string userName = "toto";
const auto contact = userName + "@" + domain;
const auto sipUri = "sip:"s + contact;

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

void rejectUnauthReq() {
	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::AuthOpenIDConnect/enabled", "true"},
	              {"module::AuthOpenIDConnect/authorization-server", "totoserver"},
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
		string clientA2 = "TeddyBear"s + "@" + domain;
		// clang-format off
		string request(
		    "MESSAGE "s + clientA2 + " SIP/2.0\r\n" +
			"Max-Forwards: 5\r\n"
			"To: <" + clientA2 + ">\r\n"
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
	const auto issuer = "example.org";
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
		BC_ASSERT_CPP_EQUAL(readParamValue(authParams, "authz-server"), issuer);
		BC_ASSERT_CPP_EQUAL(readParamValue(authParams, "realm"), realm);
	}

	// generate a valid authorization
	jwt::jwt_object obj{jwt::params::algorithm("RS256"), jwt::params::secret(kRsaPrivKey)};
	obj.add_claim("iss", issuer);
	obj.add_claim("sip_identity", sipUri);
	obj.add_claim("exp", chrono::system_clock::now() + 60s);
	const auto token = obj.signature();
	const auto authorization = string("Authorization: Bearer token=\""s + token + "\"\r\n");

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

TestSuite _("AuthOpenIDConnect",
            {
                CLASSY_TEST(rejectUnauthReq),
                CLASSY_TEST(bearerAuth),
            });
} // namespace