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

#include <string>
#include <string_view>

#include "auth-utils.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/digest.hh"
#include "utils/server/proxy-server.hh"
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
const auto pwd = "totoDu38";
const auto contact = userName + "@" + domain;
const auto sipUri = "sip:"s + contact;
const auto md5HA1 = Md5().compute<string>(userName + ":" + domain + ":" + pwd);
const auto sha256HA1 = Sha256().compute<string>(userName + ":" + domain + ":" + pwd);
const auto clientA2 = "sip:user2@"s + domain;

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

// Send a REGISTER request of a user of domain.
// Expect the proxy to reply 401 unauthorized and then answer the challenge.
void digestQopAuth() {
	// clang-format off
	const string authDb("version:1\n\n"s
						+ contact + " clrtxt:"+ pwd + " ;\n");
	// clang-format on
	TempFile authFile(authDb);

	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::Authentication/enabled", "true"},
	              {"module::Authentication/file-path", authFile.getFilename()},
	              {"module::Authentication/auth-domains", domain},
	              {"module::Authentication/disable-qop-auth", "false"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	string realm{}, qop{}, nonce{}, opaque{};

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
		realm = readParamValue(authParams, "realm=");
		BC_ASSERT_CPP_EQUAL(realm, string(domain));

		qop = readParamValue(authParams, "qop=");
		BC_ASSERT(!qop.empty()); // optional for backward compatibility but require by RFC 2617, RFC 3261 22.4
		BC_ASSERT_CPP_EQUAL(qop, string("auth")); // a valid qop is "auth,auth-int" but server only supports "auth"

		nonce = readParamValue(authParams, "nonce=");
		BC_ASSERT(!nonce.empty());

		opaque = readParamValue(authParams, "opaque=");
		BC_ASSERT(!opaque.empty());
	}

	auto generateAuthorization = [&](const char* nc, const char* cnonce) {
		const auto HA2 = Md5().compute<string>("REGISTER:"s + sipUri);
		const auto response =
		    Md5().compute<string>(md5HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2);
		// clang-format off
	return string(
			"Authorization: Digest username=\""s + userName + "\","
				" realm=\"" + realm + "\","
				" nonce=\"" + nonce + "\","
				" uri="+ sipUri + ","
				" qop=\"" + qop + "\","
				" nc=\"" + nc + "\","
				" cnonce=\"" + cnonce + "\","
				" response=\"" + response + "\","
				" opaque=\"" + opaque + "\"\r\n");
		// clang-format on
	};

	// REGISTER with a valid Authorization header
	{
		const auto nc = "00000001";
		const auto cnonce = "0a4f222a";
		const auto request = registerRequest(sipUri, "2", generateAuthorization(nc, cnonce));
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}

	// REGISTER with the same parameters except nc which is incremented by 1 and a new cnonce
	const auto nc = "00000002";
	{
		const auto cnonce = "0bb1113b";
		const auto request = registerRequest(sipUri, "3", generateAuthorization(nc, cnonce));
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}

	// Send an invalid REGISTER while nc is not incremented
	{
		const auto cnonce = "0cc4413c";
		const auto request = registerRequest(sipUri, "4", generateAuthorization(nc, cnonce));
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_401_unauthorized);

		const auto* sipMsg = transaction->getResponse()->getSip();
		BC_HARD_ASSERT(sipMsg != nullptr);
		const auto* authMsg = sipMsg->sip_www_authenticate;
		BC_HARD_ASSERT(authMsg != nullptr);
		const auto* authParams = authMsg->au_params;
		BC_HARD_ASSERT(authParams != nullptr);
		const auto newNonce = readParamValue(authParams, "nonce=");
		BC_ASSERT(!newNonce.empty());
		BC_ASSERT_FALSE(newNonce == nonce);
	}
}

// Send a REGISTER request of a user of domain.
// Expect the proxy to reply 401 unauthorized and then answer the challenge.
void digestQopDisable() {
	// clang-format off
	const string authDb("version:1\n\n"s
						+ contact + " clrtxt:"+ pwd + " ;\n");
	// clang-format on
	TempFile authFile(authDb);

	Server proxy({
	    {"module::Registrar/reg-domains", "*"},
	    {"module::Authentication/enabled", "true"},
	    {"module::Authentication/file-path", authFile.getFilename()},
	    {"module::Authentication/auth-domains", domain},
	    {"module::Authentication/disable-qop-auth", "true"},
	});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	string realm{}, nonce{}, opaque{};
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
		realm = readParamValue(authParams, "realm=");
		BC_ASSERT_CPP_EQUAL(realm, string(domain));

		// qop is not present
		BC_ASSERT(msg_params_find(authParams, "qop=") == nullptr);

		nonce = readParamValue(authParams, "nonce=");
		BC_HARD_ASSERT(!nonce.empty());

		opaque = readParamValue(authParams, "opaque=");
		BC_ASSERT(!opaque.empty());
	}

	const auto HA2 = Md5().compute<string>("REGISTER:"s + sipUri);
	const auto response = Md5().compute<string>(md5HA1 + ":" + nonce + ":" + HA2);
	// clang-format off
	string authorization(
		"Authorization: Digest username=\""s + userName + "\","
			" realm=\"" + realm + "\","
			" nonce=\"" + nonce + "\","
			" uri="+ sipUri + ","
			" response=\"" + response + "\","
			" opaque=\"" + opaque + "\"\r\n");
	// clang-format on

	// REGISTER with a valid Authorization header
	{
		const auto request = registerRequest(sipUri, "2", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}

	// REGISTER with the same parameters, expect to receive a valid response
	{
		// nonce remains valid (nonce-expires is only used with Qop)
		const auto request = registerRequest(sipUri, "3", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_200_ok);
	}
}

// Send a MESSAGE request to a user of domain.
// Expect the proxy to reply 407 proxy_auth_required and then answer the challenge.
void digestQopProxyAuth() {
	// clang-format off
	const string authDb("version:1\n\n"s
						+ contact + " clrtxt:"+ pwd + " ;\n");
	// clang-format on
	TempFile authFile(authDb);
	TempFile regFile("<" + clientA2 + "> <sip:127.0.0.1:5460>");

	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::Registrar/static-records-file", regFile.getFilename()},
	              {"module::Authentication/enabled", "true"},
	              {"module::Authentication/file-path", authFile.getFilename()},
	              {"module::Authentication/auth-domains", domain},
	              {"module::Authentication/disable-qop-auth", "false"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	auto messageRequest = [](const std::string& CSeq, const string& addField = "") {
		// clang-format off
	return string(
	    "MESSAGE "s + clientA2 + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientA2 + ">\r\n"
		"From: " + userName + " <" + sipUri + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: " + CSeq + " MESSAGE\r\n"
		"Contact: <" + sipUri + ";transport=tcp>\r\n"
		+ addField +
		"Content-Type: text/plain\r\n"
		"C'est Toto !\r\n");
		// clang-format on
	};

	string realm{}, qop{}, nonce{}, opaque{};
	{
		// first MESSAGE request is rejected, server reply with authentication parameters
		const auto request = messageRequest("1");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_407_proxy_auth_required);

		const auto* sipMsg = transaction->getResponse()->getSip();
		BC_HARD_ASSERT(sipMsg != nullptr);
		const auto* authMsg = sipMsg->sip_proxy_authenticate;
		BC_HARD_ASSERT(authMsg != nullptr);
		const auto* authParams = authMsg->au_params;
		BC_HARD_ASSERT(authParams != nullptr);
		realm = readParamValue(authParams, "realm=");
		BC_ASSERT_CPP_EQUAL(realm, string(domain));

		qop = readParamValue(authParams, "qop=");
		BC_ASSERT_CPP_EQUAL(qop, string("auth")); // a valid qop is "auth,auth-int" but server only supports "auth"

		nonce = readParamValue(authParams, "nonce=");
		BC_ASSERT(!nonce.empty());

		opaque = readParamValue(authParams, "opaque=");
		BC_ASSERT(!opaque.empty());
	}

	// MESSAGE with a valid Authorization header
	{
		const auto nc = "00000001";
		const auto cnonce = "0a4f222a";
		const auto HA2 = Md5().compute<string>("MESSAGE:" + sipUri);
		const auto response =
		    Md5().compute<string>(md5HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2);
		// clang-format off
		string authorization(
				"Proxy-Authorization: Digest username=\""s + userName + "\","
					" realm=\"" + realm + "\","
					" nonce=\"" + nonce + "\","
					" uri="+ sipUri + ","
					" qop=\"" + qop + "\","
					" nc=\"" + nc + "\","
					" cnonce=\"" + cnonce + "\","
					" response=\"" + response + "\","
					" opaque=\"" + opaque + "\"\r\n");
		// clang-format on

		const auto request = messageRequest("2", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 202);
	}
}

// Check which algortihms are present in the www-Authenticate header according to the server configuration.
void digestAlgorithmSelection() {
	const auto firstRequest = registerRequest(sipUri, "1");

	// first REGISTER request is rejected, server reply with authentication parameters
	auto testAlgo = [&firstRequest](const TempFile& file, const char* algo) {
		Server proxy({{"module::Registrar/reg-domains", "*"},
		              {"module::Authentication/enabled", "true"},
		              {"module::Authentication/file-path", file.getFilename()},
		              {"module::Authentication/auth-domains", domain},
		              {"module::Authentication/available-algorithms", algo}});

		const auto& root = proxy.getRoot();
		proxy.start();
		NtaAgent UAClient(root, "sip:127.0.0.1:0");

		const auto firstTransaction = sendRequest(UAClient, root, firstRequest, proxy.getFirstPort());
		checkResponse(firstTransaction, response_401_unauthorized);

		const auto* sipMsg = firstTransaction->getResponse()->getSip();
		BC_HARD_ASSERT(sipMsg != nullptr);
		const auto* authMsg = sipMsg->sip_www_authenticate;
		vector<string> algorithms;
		while (authMsg != nullptr) {
			const auto* authParams = authMsg->au_params;
			BC_HARD_ASSERT(authParams != nullptr);
			algorithms.emplace_back(readParamValue(authParams, "algorithm="));
			authMsg = authMsg->au_next;
		}
		return algorithms;
	};

	const string dbHdr("version:1\n\n");
	{
		// Database has user md5 & sha256 HA1
		TempFile bothHashDatabase(dbHdr + contact + " md5:" + md5HA1 + " sha256:" + sha256HA1 + " ;\n");
		{
			auto algorithms = testAlgo(bothHashDatabase, "MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
		}
		{
			auto algorithms = testAlgo(bothHashDatabase, "SHA-256");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
		}
		{
			auto algorithms = testAlgo(bothHashDatabase, "MD5,SHA-256");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 2);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
			BC_ASSERT_CPP_EQUAL(algorithms[1], string("SHA-256"));
		}
		{
			auto algorithms = testAlgo(bothHashDatabase, "SHA-256,MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 2);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
			BC_ASSERT_CPP_EQUAL(algorithms[1], string("MD5"));
		}
	}

	{
		// Database has only md5 HA1
		TempFile md5Database(dbHdr + contact + " md5:" + md5HA1 + " ;\n");
		{
			auto algorithms = testAlgo(md5Database, "MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
		}
		{
			auto algorithms = testAlgo(md5Database, "SHA-256");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
		}
		{
			auto algorithms = testAlgo(md5Database, "SHA-256,MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
		}
	}

	{
		// Database has only sha256 HA1
		TempFile sha256Database(dbHdr + contact + " sha256:" + sha256HA1 + " ;\n");
		{
			auto algorithms = testAlgo(sha256Database, "MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
		}
		{
			auto algorithms = testAlgo(sha256Database, "SHA-256");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
		}
		{
			auto algorithms = testAlgo(sha256Database, "SHA-256,MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
		}
	}

	{
		// Empty database
		TempFile emptyDatabase(dbHdr);
		{
			auto algorithms = testAlgo(emptyDatabase, "MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
		}
		{
			auto algorithms = testAlgo(emptyDatabase, "SHA-256");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 1);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
		}
		{
			auto algorithms = testAlgo(emptyDatabase, "MD5,SHA-256");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 2);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("MD5"));
			BC_ASSERT_CPP_EQUAL(algorithms[1], string("SHA-256"));
		}
		{
			auto algorithms = testAlgo(emptyDatabase, "SHA-256,MD5");
			BC_HARD_ASSERT_CPP_EQUAL(algorithms.size(), 2);
			BC_ASSERT_CPP_EQUAL(algorithms[0], string("SHA-256"));
			BC_ASSERT_CPP_EQUAL(algorithms[1], string("MD5"));
		}
	}
}

string messageRequestWithPPI(const string& fromUri, const string& CSeq, const string& authHdr) {
	// clang-format off
	return string(
	    "MESSAGE "s + clientA2 + " SIP/2.0\r\n"
		"Max-Forwards: 5\r\n"
		"To: user2 <" + clientA2 + ">\r\n"
		"From: <" + fromUri + ">;tag=465687829\r\n"
		"Call-ID: 1053183492\r\n"
		"CSeq: " + CSeq + " MESSAGE\r\n"
		"Contact: <" + sipUri + ";transport=udp>\r\n"
		+ authHdr +
		"Content-Type: text/plain\r\n"
		"P-Preferred-Identity: " + userName + " <" + sipUri + ">\r\n"
		"Content-Length: 11\r\n\r\n"
		"Who am I?\r\n");
	// clang-format on
}

// Send a MESSAGE request using a P-Preferred-Identity header.
// Expect the proxy to reply 407 proxy_auth_required for the PPI user and then answer the challenge.
void acceptAnonymousMessage() {
	// clang-format off
	const string authDb("version:1\n\n"s
						+ contact + " clrtxt:"+ pwd + " ;\n");
	// clang-format on
	TempFile authFile(authDb);
	TempFile regFile("<" + clientA2 + "> <sip:127.0.0.1:5460>");

	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::Registrar/static-records-file", regFile.getFilename()},
	              {"module::Authentication/enabled", "true"},
	              {"module::Authentication/file-path", authFile.getFilename()},
	              {"module::Authentication/auth-domains", domain},
	              {"module::Authentication/disable-qop-auth", "true"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	const auto anonymousUri = "sip:anonymous@anonymous.invalid"s;
	string realm{}, nonce{}, opaque{};
	{
		// first MESSAGE request is rejected, server reply with authentication parameters
		const auto request = messageRequestWithPPI(anonymousUri, "22", "");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_407_proxy_auth_required);

		const auto* sipMsg = transaction->getResponse()->getSip();
		BC_HARD_ASSERT(sipMsg != nullptr);
		const auto* authMsg = sipMsg->sip_proxy_authenticate;
		BC_HARD_ASSERT(authMsg != nullptr);
		const auto* authParams = authMsg->au_params;
		BC_HARD_ASSERT(authParams != nullptr);
		realm = readParamValue(authParams, "realm=");
		BC_ASSERT_CPP_EQUAL(realm, string(domain));
		nonce = readParamValue(authParams, "nonce=");
		BC_ASSERT(!nonce.empty());
		opaque = readParamValue(authParams, "opaque=");
		BC_ASSERT(!opaque.empty());
	}

	const auto HA2 = Md5().compute<string>("MESSAGE:"s + sipUri);
	const auto response = Md5().compute<string>(md5HA1 + ":" + nonce + ":" + HA2);
	// clang-format off
	string authorization(
		"Proxy-Authorization: Digest username=\""s + userName + "\","
			" realm=\"" + realm + "\","
			" nonce=\"" + nonce + "\","
			" uri="+ sipUri + ","
			" response=\"" + response + "\","
			" opaque=\"" + opaque + "\"\r\n");
	// clang-format on

	{
		const auto request = messageRequestWithPPI(anonymousUri, "23", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_202_Accepted);
	}
}

// Send a MESSAGE request using a P-Preferred-Identity header but with trying to be another user.
// Expect the proxy to reply 407 proxy_auth_required for the From user, PPI user cannot answer the challenge.
void rejectIdentityFraudMessage() {
	const auto anotherContact = "anotherUsr"s + "@" + domain;
	// clang-format off
	const string authDb("version:1\n\n"s
						+ contact + " clrtxt:"+ pwd + " ;\n"
						+ anotherContact + " clrtxt:anotherPassword ;\n");
	// clang-format on
	TempFile authFile(authDb);
	TempFile regFile("<" + clientA2 + "> <sip:127.0.0.1:5460>");

	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::Registrar/static-records-file", regFile.getFilename()},
	              {"module::Authentication/enabled", "true"},
	              {"module::Authentication/file-path", authFile.getFilename()},
	              {"module::Authentication/auth-domains", domain},
	              {"module::Authentication/disable-qop-auth", "true"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	const auto anotherContactUri = "sip:"s + anotherContact;
	string realm{}, nonce{}, opaque{};
	{
		// first MESSAGE request is rejected, server reply with authentication parameters
		const auto request = messageRequestWithPPI(anotherContactUri, "22", "");
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, response_407_proxy_auth_required);

		const auto* sipMsg = transaction->getResponse()->getSip();
		BC_HARD_ASSERT(sipMsg != nullptr);
		const auto* authMsg = sipMsg->sip_proxy_authenticate;
		BC_HARD_ASSERT(authMsg != nullptr);
		const auto* authParams = authMsg->au_params;
		BC_HARD_ASSERT(authParams != nullptr);
		realm = readParamValue(authParams, "realm=");
		BC_ASSERT_CPP_EQUAL(realm, string(domain));
		nonce = readParamValue(authParams, "nonce=");
		BC_ASSERT(!nonce.empty());
		opaque = readParamValue(authParams, "opaque=");
		BC_ASSERT(!opaque.empty());
	}

	const auto HA2 = Md5().compute<string>("MESSAGE:"s + sipUri);
	const auto response = Md5().compute<string>(md5HA1 + ":" + nonce + ":" + HA2);
	// clang-format off
	string authorization(
		"Proxy-Authorization: Digest username=\""s + userName + "\","
			" realm=\"" + realm + "\","
			" nonce=\"" + nonce + "\","
			" uri="+ sipUri + ","
			" response=\"" + response + "\","
			" opaque=\"" + opaque + "\"\r\n");
	// clang-format on

	{
		const auto request = messageRequestWithPPI(anotherContactUri, "23", authorization);
		const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
		checkResponse(transaction, {403, "Forbidden"});
	}
}

// Verify that 'count-password-found' and 'count-password-not-found' are correctly incremented.
void passwordCounters() {
	const string authDb("version:1\n\n"s + contact + " clrtxt:" + pwd + " ;\n");
	TempFile authFile(authDb);

	Server proxy({
	    {"module::Registrar/reg-domains", "*"},
	    {"module::Authentication/enabled", "true"},
	    {"module::Authentication/file-path", authFile.getFilename()},
	    {"module::Authentication/auth-domains", domain},
	    {"module::Authentication/disable-qop-auth", "false"},
	});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:127.0.0.1:0");

	// Send a REGISTER request to the proxy and try to answer to the challenge.
	const auto tryToRegister = [&](const std::string& uri, const Response& expected) {
		string realm{}, qop{}, nonce{}, opaque{};

		{
			const auto request = registerRequest(uri, "1");
			const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
			if (expected.msg == response_403_forbidden.msg) {
				checkResponse(transaction, response_403_forbidden);
				return;
			}
			checkResponse(transaction, response_401_unauthorized);

			const auto* sipMsg = transaction->getResponse()->getSip();
			BC_HARD_ASSERT(sipMsg != nullptr);
			const auto* authMsg = sipMsg->sip_www_authenticate;
			BC_HARD_ASSERT(authMsg != nullptr);
			const auto* authParams = authMsg->au_params;
			BC_HARD_ASSERT(authParams != nullptr);
			realm = readParamValue(authParams, "realm=");
			BC_ASSERT_CPP_EQUAL(realm, string(domain));

			qop = readParamValue(authParams, "qop=");
			BC_ASSERT(!qop.empty()); // optional for backward compatibility but require by RFC 2617, RFC 3261 22.4
			BC_ASSERT_CPP_EQUAL(qop,
			                    string("auth")); // a valid qop is "auth,auth-int" but server only supports "auth"

			nonce = readParamValue(authParams, "nonce=");
			BC_ASSERT(!nonce.empty());

			opaque = readParamValue(authParams, "opaque=");
			BC_ASSERT(!opaque.empty());
		}

		{
			auto generateAuthorization = [&](const char* nc, const char* cnonce) {
				const auto HA2 = Md5().compute<string>("REGISTER:"s + uri);
				const auto response =
				    Md5().compute<string>(md5HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2);
				// clang-format off
				return string(
						"Authorization: Digest username=\""s + userName + "\","
							" realm=\"" + realm + "\","
							" nonce=\"" + nonce + "\","
							" uri="+ uri + ","
							" qop=\"" + qop + "\","
							" nc=\"" + nc + "\","
							" cnonce=\"" + cnonce + "\","
							" response=\"" + response + "\","
							" opaque=\"" + opaque + "\"\r\n");
				// clang-format on
			};

			const auto nc = "00000001";
			const auto cnonce = "0a4f222a";
			const auto request = registerRequest(uri, "2", generateAuthorization(nc, cnonce));
			const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
			checkResponse(transaction, expected);
		}
	};

	// Successful registration should increment 'count-password-found' by 1.
	tryToRegister(sipUri, response_200_ok);

	const auto* moduleConfig = proxy.getConfigManager()->getRoot()->get<GenericStruct>("module::Authentication");
	BC_ASSERT_CPP_EQUAL(moduleConfig->get<StatCounter64>("count-password-found")->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleConfig->get<StatCounter64>("count-password-not-found")->read(), 0);

	// Failed registration should increment 'count-password-not-found' by 1.
	tryToRegister("sip:unkown@"s + domain, {403, "Forbidden"});

	BC_ASSERT_CPP_EQUAL(moduleConfig->get<StatCounter64>("count-password-found")->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleConfig->get<StatCounter64>("count-password-not-found")->read(), 1);

	// Failed registration (wrong domain) should not increase any of the counters.
	tryToRegister("sip:unkown@sip.wrong.test.org", response_403_forbidden);

	BC_ASSERT_CPP_EQUAL(moduleConfig->get<StatCounter64>("count-password-found")->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleConfig->get<StatCounter64>("count-password-not-found")->read(), 1);
}

TestSuite _{
    "AuthDigest",
    {
        CLASSY_TEST(digestQopAuth),
        CLASSY_TEST(digestQopDisable),
        CLASSY_TEST(digestQopProxyAuth),
        CLASSY_TEST(digestAlgorithmSelection),
        CLASSY_TEST(acceptAnonymousMessage),
        CLASSY_TEST(rejectIdentityFraudMessage),
        CLASSY_TEST(passwordCounters),
    },
};
} // namespace