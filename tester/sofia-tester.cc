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

#include <future>

#include "sofia-sip/http.h"
#include "sofia-sip/nta.h"
#include "sofia-sip/nta_stateless.h"
#include "sofia-sip/nth.h"
#include "sofia-sip/tport_tag.h"

#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/tls-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tls/certificate.hh"
#include "utils/tls/private-key.hh"
#include "utils/tmp-dir.hh"
#include "utils/transport/tls-connection.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester::sofia_tester_suite {
namespace {

/*
 * Test Sofia-SIP nth_engine, with TLS SNI enabled/disabled.
 */
template <bool tlsSniEnabled>
void nthEngineWithSni() {
	SuRoot root{};
	TlsServer server{};
	auto requestReceived = false;
	auto requestMatch = async(launch::async, [&server, &requestReceived]() {
		server.accept(tlsSniEnabled ? "127.0.0.1" : ""); // SNI checks are done in TlsServer::accept.
		server.read();
		server.send("Status: 200");
		return requestReceived = true;
	});

	const auto url = "https://127.0.0.1:" + to_string(server.getPort());
	auto* engine = nth_engine_create(root.getCPtr(), TPTAG_TLS_SNI(tlsSniEnabled), TAG_END());

	auto* request =
	    nth_client_tcreate(engine, nullptr, nullptr, http_method_get, "GET", URL_STRING_MAKE(url.c_str()), TAG_END());

	if (request == nullptr) {
		BC_FAIL("No request sent.");
	}

	CoreAssert<kNoSleep>(root)
	    .waitUntil(100ms, [&requestReceived] { return LOOP_ASSERTION(requestReceived); })
	    .assert_passed();

	BC_ASSERT_TRUE(requestMatch.get());
	nth_client_destroy(request);
	nth_engine_destroy(engine);
}

const auto UDP = "transport=udp"s;
const auto TCP = "transport=tcp"s;
const auto TLS = "transport=tls"s;

/*
 * Test behavior of Sofia-SIP when the size of the data read from the socket is less than, equal to, or greater than the
 * agent's message maxsize.
 * 1. Send several requests to the UAS.
 * 2. Iterate on the main loop, so the UAS will collect pending requests from the socket.
 * 3. UAS should process all collected data even if the number of data (in bytes) exceeds agent's message maxsize.
 *
 * @tparam maxsize     Sofia-SIP NTA msg maxsize
 * @tparam nbRequests  number of requests to send
 * @tparam transport   the transport to use in this test: [UDP, TCP, TLS]
 *
 * Generated requests have a size of 414 bytes.
 * Info:
 * - 10 * 414 = 4140  bytes
 * - 15 * 414 = 6210  bytes
 * - 20 * 414 = 8280  bytes
 * - 40 * 414 = 16560 bytes
 */
template <int maxsize, int nbRequests, const string& transport>
void collectAndParseDataFromSocket() {
	const auto stubUser = "stub-user"s;
	const auto stubHost = "localhost"s;
	const auto stubIdentity = "sip:" + stubUser + "@" + stubHost;

	const auto serverSuRoot = make_shared<SuRoot>();
	Server server{{
	                  {"global/transports", (transport == "transport=tls" ? "sips" : "sip") +
	                                            ":127.0.0.1:0;tls-verify-incoming=0;tls-verify-outgoing=0;"s},
	                  {"global/sofia-level", "9"},
	                  {"module::Registrar/reg-domains", "*"},
	                  {"global/tls-certificates-file", bcTesterRes("cert/self.signed.cert.test.pem")},
	                  {"global/tls-certificates-private-key", bcTesterRes("cert/self.signed.key.test.pem")},
	                  {"module::DoSProtection/enabled", "false"},
	              },
	              serverSuRoot};
	server.start();
	nta_agent_set_params(server.getAgent()->getSofiaAgent(), NTATAG_MAXSIZE(maxsize), TAG_END());

	const auto clientSuRoot = make_shared<SuRoot>();
	NtaAgent client{
	    clientSuRoot,
	    transport != TLS ? toSofiaSipUrlUnion("sip:127.0.0.1:0;" + transport) : reinterpret_cast<url_string_t*>(-1),
	    [](nta_agent_magic_t*, nta_agent_t* agent, msg_t* msg, sip_t*) -> int {
		    nta_msg_treply(agent, msg, 202, "Accepted", TAG_END());
		    return 0;
	    },
	    nullptr,
	    NTATAG_UA(false),
	};

	if (transport == TLS) {
		const auto certs = bcTesterRes("cert/self.signed.legacy");
		const auto* ciphers = "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL";
		client.addTransport(
		    "sips:127.0.0.1:0;" + transport, TPTAG_CERTIFICATE(certs.c_str()), TPTAG_CERTIFICATE_CA_FILE(""),
		    TPTAG_TLS_VERIFY_POLICY(tport_tls_verify_policy::TPTLS_VERIFY_NONE), TPTAG_TLS_CIPHERS(ciphers));
	}

	CoreAssert<kNoSleep> asserter{serverSuRoot, clientSuRoot};
	const auto routeUri = "sip:127.0.0.1:"s + server.getFirstPort() + ";" + transport;

	// Register client.
	auto requestRegister = make_unique<MsgSip>();
	requestRegister->makeAndInsert<SipHeaderRequest>(sip_method_register, stubIdentity);
	requestRegister->makeAndInsert<SipHeaderFrom>(stubIdentity, "stub-from-tag");
	requestRegister->makeAndInsert<SipHeaderTo>(stubIdentity);
	requestRegister->makeAndInsert<SipHeaderCallID>("stub-call-id");
	requestRegister->makeAndInsert<SipHeaderCSeq>(20u, sip_method_register);
	requestRegister->makeAndInsert<SipHeaderContact>("<" + stubIdentity + ";" + transport + ">");
	requestRegister->makeAndInsert<SipHeaderExpires>(10);
	const auto registration = client.createOutgoingTransaction(std::move(requestRegister), routeUri);

	asserter.iterateUpTo(
	            0x20, [&registration] { return LOOP_ASSERTION(registration->isCompleted()); }, 100ms)
	    .hard_assert_passed();

	// Send requests to UAS.
	vector<shared_ptr<NtaOutgoingTransaction>> transactions{};
	for (int requestId = 0; requestId < nbRequests; ++requestId) {
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_subscribe, stubIdentity);
		request->makeAndInsert<SipHeaderFrom>(stubIdentity, "stub-from-tag");
		request->makeAndInsert<SipHeaderTo>(stubIdentity);
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_subscribe);
		request->makeAndInsert<SipHeaderCallID>("stub-call-id-" + to_string(10 + requestId));
		request->makeAndInsert<SipHeaderMaxForwards>(70u);
		request->makeAndInsert<SipHeaderRoute>("<sip:127.0.0.1:"s + client.getFirstPort() + ";" + transport + ";lr>");
		request->makeAndInsert<SipHeaderEvent>("reg");
		request->makeAndInsert<SipHeaderExpires>(10);
		request->makeAndInsert<SipHeaderContact>("<" + stubIdentity + ";" + transport + ">");

		transactions.push_back(client.createOutgoingTransaction(std::move(request), routeUri));
	}

	asserter
	    .iterateUpTo(
	        0x20,
	        [&transactions] {
		        for (const auto& transaction : transactions) {
			        FAIL_IF(!transaction->isCompleted());
		        }
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Keep this so if the CoreAssert fails we can get debug information from these checks.
	for (const auto& transaction : transactions) {
		BC_ASSERT(transaction->isCompleted());
	}
}

/*
 * Test parsing of one SIP request whose size exceeds msg maxsize.
 * Note: Sofia-SIP cannot parse a SIP request that exceeds the maximum acceptable size of an incoming message.
 *
 * Expected behavior: the connection should be closed between the client and the server.
 */
void collectAndTryToParseSIPMessageThatExceedsMsgMaxsize() {
	int maxsize = msg_min_size * 2;
	const auto suRoot = make_shared<SuRoot>();
	NtaAgent server{suRoot, "sip:127.0.0.1:0;transport=tcp", nullptr, nullptr, NTATAG_MAXSIZE(maxsize)};
	NtaAgent client{suRoot, "sip:127.0.0.1:0;transport=tcp", nullptr, nullptr, NTATAG_UA(false)};

	// Send requests to UAS.
	const auto routeUri = "sip:127.0.0.1:"s + server.getFirstPort() + ";transport=tcp";
	auto request = make_unique<MsgSip>();
	request->makeAndInsert<SipHeaderRequest>(sip_method_register, "sip:localhost");
	request->makeAndInsert<SipHeaderFrom>("sip:stub-user@localhost", "stub-from-tag");
	request->makeAndInsert<SipHeaderTo>("sip:stub-user@localhost");
	request->makeAndInsert<SipHeaderCallID>("stub-call-id");
	request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_register);
	// Voluntarily add several headers to make SIP message exceeds msg maxsize.
	for (int contactId = 0; contactId < 20; ++contactId) {
		request->makeAndInsert<SipHeaderContact>("<sip:stub-user@localhost;transport=tcp>");
	}
	request->makeAndInsert<SipHeaderExpires>(10);
	const auto transaction = client.createOutgoingTransaction(std::move(request), routeUri);

	const auto clientConnectionToServerIsAlive = [&client]() {
		return tport_secondary(tport_next(client.getTransports())) != nullptr;
	};
	BC_HARD_ASSERT(clientConnectionToServerIsAlive() == true);

	CoreAssert<kNoSleep>{suRoot}
	    .iterateUpTo(
	        0x20,
	        [&] {
		        FAIL_IF(clientConnectionToServerIsAlive());
		        FAIL_IF(transaction->isCompleted());
		        return ASSERTION_PASSED();
	        },
	        100ms)
	    .assert_passed();
}

/*
 * Test that Sofia-SIP closes connections that were inactive for more than 'idle-timeout' seconds.
 * This should be the case even if no data has ever passed through this connection.
 */
template <const string& transportType>
void connectionToServerIsRemovedAfterIdleTimeoutTriggers() {
	auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	privateKey.writeToFile(keyPath);
	const TlsCertificate cert{privateKey};
	cert.writeToFile(certPath);

	const auto transport = (transportType == "transport=tls" ? "sips"s : "sip"s) + ":127.0.0.1:0";
	Server proxy{{
	    {"global/transports", transport},
	    {"global/idle-timeout", "1"},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	}};
	proxy.start();

	// Create connection to server.
	TlsConnection connection{"127.0.0.1", proxy.getFirstPort(), "", ""};
	connection.connect();
	BC_ASSERT(connection.isConnected());

	// Verify it is now disconnected, closed from the server because of inactivity.
	vector<char> data{};
	CoreAssert{proxy}
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        std::ignore = connection.read(data, 32);
		        FAIL_IF(connection.isConnected());
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

void updateTlsCertificate() {
	auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	privateKey.writeToFile(keyPath);
	const TlsCertificate cert{privateKey};
	cert.writeToFile(certPath);
	const auto ciphers = "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL";
	const auto policy = SSL_VERIFY_NONE;

	Server proxy{{
	    {"global/transports",
	     "sips:sip.example.org:0;maddr=127.0.0.1 sip:sip.example.org:0;transport=tcp;maddr=127.0.0.1"},
	    {"module::DoSProtection/enabled", "false"},
	    {"global/tls-certificates-check-interval", "1min"},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	    {"global/tls-ciphers", ciphers},
	}};
	proxy.start();

	const auto proxyUri = "sips:sip.example.org:"s + proxy.getFirstPort() + ";maddr=127.0.0.1";
	Url url{proxyUri};

	// No changes
	{
		auto error = nta_agent_update_tport_certificates(
		    proxy.getAgent()->getSofiaAgent(), (const url_string_t*)url.get(), TPTAG_CERTIFICATE_FILE(certPath.c_str()),
		    TPTAG_CERTIFICATE_PRIVATE_KEY(keyPath.c_str()), TPTAG_TLS_PASSPHRASE(""), TPTAG_TLS_CIPHERS(ciphers),
		    TPTAG_TLS_VERIFY_POLICY(policy), TAG_END());
		BC_ASSERT_CPP_EQUAL(error, 0);
	}
	{
		// Mismatch the key
		const TlsPrivateKey newKey{};
		newKey.writeToFile(keyPath);

		auto error = nta_agent_update_tport_certificates(
		    proxy.getAgent()->getSofiaAgent(), (const url_string_t*)url.get(), TPTAG_CERTIFICATE_FILE(certPath.c_str()),
		    TPTAG_CERTIFICATE_PRIVATE_KEY(keyPath.c_str()), TPTAG_TLS_PASSPHRASE(""), TPTAG_TLS_CIPHERS(ciphers),
		    TPTAG_TLS_VERIFY_POLICY(policy), TAG_END());
		BC_ASSERT_CPP_NOT_EQUAL(error, 0);

		// New certificate matching the key
		const TlsCertificate newCert{newKey};
		newCert.writeToFile(certPath);

		error = nta_agent_update_tport_certificates(
		    proxy.getAgent()->getSofiaAgent(), (const url_string_t*)url.get(), TPTAG_CERTIFICATE_FILE(certPath.c_str()),
		    TPTAG_CERTIFICATE_PRIVATE_KEY(keyPath.c_str()), TPTAG_TLS_PASSPHRASE(""), TPTAG_TLS_CIPHERS(ciphers),
		    TPTAG_TLS_VERIFY_POLICY(policy), TAG_END());
		BC_ASSERT_CPP_EQUAL(error, 0);
	}
	// Mismatch the certificate
	{
		const TlsPrivateKey anotherKey{};
		const TlsCertificate newCert{anotherKey};
		newCert.writeToFile(certPath);

		auto error = nta_agent_update_tport_certificates(
		    proxy.getAgent()->getSofiaAgent(), (const url_string_t*)url.get(), TPTAG_CERTIFICATE_FILE(certPath.c_str()),
		    TPTAG_CERTIFICATE_PRIVATE_KEY(keyPath.c_str()), TPTAG_TLS_PASSPHRASE(""), TPTAG_TLS_CIPHERS(ciphers),
		    TPTAG_TLS_VERIFY_POLICY(policy), TAG_END());
		BC_ASSERT_CPP_NOT_EQUAL(error, 0);
	}
}

void updateTlsWithExpiredCertificate() {
	auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	privateKey.writeToFile(keyPath);
	const TlsCertificate cert{privateKey};
	cert.writeToFile(certPath);
	const auto ciphers = "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL";
	const auto policy = SSL_VERIFY_NONE;
	const string transportUri = "sips:127.0.0.1";

	Server proxy{{
	    {"global/transports", transportUri + ":0"},
	    {"module::DoSProtection/enabled", "false"},
	    {"global/tls-certificates-check-interval", "1min"},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	    {"global/tls-ciphers", ciphers},
	}};
	proxy.start();

	const auto proxyUri = transportUri + ":" + proxy.getFirstPort();
	Url url{proxyUri};

	// Change with expired certificate
	{
		const TlsCertificate expiredCert{privateKey, -10};
		expiredCert.writeToFile(certPath);

		auto error = nta_agent_update_tport_certificates(
		    proxy.getAgent()->getSofiaAgent(), (const url_string_t*)url.get(), TPTAG_CERTIFICATE_FILE(certPath.c_str()),
		    TPTAG_CERTIFICATE_PRIVATE_KEY(keyPath.c_str()), TPTAG_TLS_PASSPHRASE(""), TPTAG_TLS_CIPHERS(ciphers),
		    TPTAG_TLS_VERIFY_POLICY(policy), TAG_END());
		BC_ASSERT_CPP_NOT_EQUAL(error, 0);
	}
}

// Check update for transports needing DNS resolution
void updateTlsCertificateNoIpSpecified() {
	auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	privateKey.writeToFile(keyPath);
	const TlsCertificate cert{privateKey};
	cert.writeToFile(certPath);
	const auto ciphers = "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL";
	const auto policy = SSL_VERIFY_NONE;

	const string transportUri = "sips:localhost";

	Server proxy{{
	    {"global/transports", transportUri + ":0"},
	    {"module::DoSProtection/enabled", "false"},
	    {"global/tls-certificates-check-interval", "1min"},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	    {"global/tls-ciphers", ciphers},
	}};
	proxy.start();

	const auto proxyUri = transportUri + ":" + proxy.getFirstPort();
	Url url{proxyUri};

	// Change with valid certificate
	{
		const TlsCertificate newCert{privateKey};
		newCert.writeToFile(certPath);

		auto error = nta_agent_update_tport_certificates(
		    proxy.getAgent()->getSofiaAgent(), (const url_string_t*)url.get(), TPTAG_CERTIFICATE_FILE(certPath.c_str()),
		    TPTAG_CERTIFICATE_PRIVATE_KEY(keyPath.c_str()), TPTAG_TLS_PASSPHRASE(""), TPTAG_TLS_CIPHERS(ciphers),
		    TPTAG_TLS_VERIFY_POLICY(policy), TAG_END());
		BC_ASSERT_CPP_EQUAL(error, 0);
	}
}

TestSuite _("Sofia-SIP",
            {
                CLASSY_TEST(nthEngineWithSni<true>),
                CLASSY_TEST(nthEngineWithSni<false>),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 5, UDP>)), // message size under maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 5, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 5, TLS>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4140, 10, UDP>)), // message size equals maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4140, 10, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4140, 10, TLS>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 15, UDP>)), // message size above maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 15, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 15, TLS>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 40, UDP>)), // message size +2x above maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 40, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 40, TLS>)),
                CLASSY_TEST(collectAndTryToParseSIPMessageThatExceedsMsgMaxsize),
                CLASSY_TEST(connectionToServerIsRemovedAfterIdleTimeoutTriggers<TCP>),
                CLASSY_TEST(connectionToServerIsRemovedAfterIdleTimeoutTriggers<TLS>),
                CLASSY_TEST(updateTlsCertificate),
                CLASSY_TEST(updateTlsWithExpiredCertificate),
                CLASSY_TEST(updateTlsCertificateNoIpSpecified),
            });

} // namespace
} // namespace flexisip::tester::sofia_tester_suite