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
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tls-server.hh"
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
 * @tparam	maxsize		Sofia-SIP NTA msg maxsize
 * @tparam	nbRequests	number of requests to send
 * @tparam	transport	indicate which transport to use in this test: [UDP, TCP, TLS]
 *
 * Generated requests have a size of 322 bytes.
 * Info:
 * - 10 * 322 = 3220  bytes
 * - 15 * 322 = 4830  bytes
 * - 20 * 322 = 6440  bytes
 * - 40 * 322 = 12880 bytes
 */
template <int maxsize, int nbRequests, const string& transport>
void collectAndParseDataFromSocket() {
	constexpr int expectedStatus = 202; // Accepted
	static const auto& stubUser = "stub-user"s;
	static const auto& stubHost = "localhost"s;
	static const auto& stubIdentity = "sip:" + stubUser + "@" + stubHost;

	// Function called on request processing.
	auto callback = [](nta_agent_magic_t*, nta_agent_t* agent, msg_t* msg, sip_t* sip) -> int {
		if (sip and sip->sip_request and sip->sip_request->rq_method == sip_method_register) {
			BC_HARD_ASSERT(sip->sip_contact != nullptr);
			BC_HARD_ASSERT_CPP_EQUAL(sip->sip_contact->m_url->url_user, stubUser);
			BC_HARD_ASSERT_CPP_EQUAL(sip->sip_contact->m_url->url_host, stubHost);
		}
		nta_msg_treply(agent, msg, expectedStatus, "Accepted", TAG_END()); // Complete generated outgoing transactions.
		return 0;
	};

	auto suRoot = make_shared<SuRoot>();
	NtaAgent server{
	    suRoot,
	    transport != TLS ? toSofiaSipUrlUnion("sip:127.0.0.1:0;" + transport) : reinterpret_cast<url_string_t*>(-1),
	    callback,
	    nullptr,
	    NTATAG_MAXSIZE(maxsize),
	};
	NtaAgent client{
	    suRoot,
	    transport != TLS ? toSofiaSipUrlUnion("sip:127.0.0.1:0;" + transport) : reinterpret_cast<url_string_t*>(-1),
	    nullptr,
	    nullptr,
	    NTATAG_UA(false),
	};

	if (transport == TLS) {
		const auto certs = bcTesterRes("cert/self.signed.legacy");
		const auto* ciphers = "HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL";
		server.addTransport(
		    "sips:127.0.0.1:0;" + transport, TPTAG_CERTIFICATE(certs.c_str()), TPTAG_CERTIFICATE_CA_FILE(""),
		    TPTAG_TLS_VERIFY_POLICY(tport_tls_verify_policy::TPTLS_VERIFY_NONE), TPTAG_TLS_CIPHERS(ciphers));
		client.addTransport(
		    "sips:127.0.0.1:0;" + transport, TPTAG_CERTIFICATE(certs.c_str()), TPTAG_CERTIFICATE_CA_FILE(""),
		    TPTAG_TLS_VERIFY_POLICY(tport_tls_verify_policy::TPTLS_VERIFY_NONE), TPTAG_TLS_CIPHERS(ciphers));
	}

	// Send requests to UAS.
	vector<shared_ptr<NtaOutgoingTransaction>> transactions{};
	const auto routeUri = "sip:localhost:"s + server.getFirstPort() + ";maddr=127.0.0.1;" + transport;
	for (int requestId = 0; requestId < nbRequests; ++requestId) {
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_register, "sip:localhost");
		request->makeAndInsert<SipHeaderFrom>(stubIdentity, "stub-from-tag");
		request->makeAndInsert<SipHeaderTo>(stubIdentity);
		request->makeAndInsert<SipHeaderCallID>("stub-call-id");
		request->makeAndInsert<SipHeaderCSeq>(20u + requestId, sip_method_register);
		request->makeAndInsert<SipHeaderContact>("<" + stubIdentity + ";" + transport + ">");
		request->makeAndInsert<SipHeaderExpires>(10);

		transactions.push_back(client.createOutgoingTransaction(std::move(request), routeUri));
	}

	// Iterate on main loop.
	CoreAssert<kNoSleep>{suRoot}
	    .waitUntil(100ms,
	               [&] {
		               for (const auto& transaction : transactions) {
			               FAIL_IF(!transaction->isCompleted());
			               FAIL_IF(transaction->getStatus() != expectedStatus);
		               }
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();

	// Keep this so if the CoreAssert fails we can get debug information from these checks.
	for (const auto& transaction : transactions) {
		BC_ASSERT(transaction->isCompleted());
		BC_ASSERT_CPP_EQUAL(transaction->getStatus(), expectedStatus);
	}
}

/*
 * Test parsing of one SIP message whose size exceeds msg maxsize.
 * Note: Sofia-SIP cannot parse a SIP message that exceeds the maximum acceptable size of an incoming message.
 */
void collectAndTryToParseSIPMessageThatExceedsMsgMaxsize() {
	int maxsize = msg_min_size * 2;
	int expectedStatus = 400; // Bad request
	auto suRoot = make_shared<SuRoot>();
	NtaAgent server{suRoot, "sip:127.0.0.1:0;transport=tcp", nullptr, nullptr, NTATAG_MAXSIZE(maxsize), TAG_END()};
	NtaAgent client{suRoot, "sip:127.0.0.1:0;transport=tcp", nullptr, nullptr, NTATAG_UA(false), TAG_END()};

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

	auto transaction = client.createOutgoingTransaction(std::move(request), routeUri);

	// Iterate on main loop.
	CoreAssert<kNoSleep>{suRoot}
	    .waitUntil(100ms,
	               [&] {
		               FAIL_IF(!transaction->isCompleted());
		               FAIL_IF(transaction->getStatus() != expectedStatus);
		               return ASSERTION_PASSED();
	               })
	    .assert_passed();
}

/*
 * Test that Sofia-SIP closes connections that were inactive for more than 'idle-timeout' seconds.
 * This should be the case even if no data has ever passed through this connection.
 */
void connectionToServerIsRemovedAfterIdleTimeoutTriggers() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0"},
	    {"global/idle-timeout", "1"},
	}};
	proxy.start();

	// Create TCP connection to server.
	auto connection = TlsConnection{"127.0.0.1", proxy.getFirstPort(), "", ""};
	connection.connect();
	BC_ASSERT(connection.isConnected());

	// Verify it is now disconnected, closed from the server because of inactivity.
	vector<char> data{};
	BC_ASSERT(CoreAssert{proxy}.iterateUpTo(
	    0x20,
	    [&]() {
		    std::ignore = connection.read(data, 32);
		    FAIL_IF(connection.isConnected());
		    return ASSERTION_PASSED();
	    },
	    2s));
}

TestSuite _("Sofia-SIP",
            {
                CLASSY_TEST(nthEngineWithSni<true>),
                CLASSY_TEST(nthEngineWithSni<false>),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 10, UDP>)), // message size under maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 10, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 10, TLS>)),
                CLASSY_TEST((collectAndParseDataFromSocket<3220, 10, UDP>)), // message size equals maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<3220, 10, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<3220, 10, TLS>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 20, UDP>)), // message size above maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 20, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 20, TLS>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 40, UDP>)), // message size +2x above maxsize
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 40, TCP>)),
                CLASSY_TEST((collectAndParseDataFromSocket<4096, 40, TLS>)),
                CLASSY_TEST(collectAndTryToParseSIPMessageThatExceedsMsgMaxsize),
                CLASSY_TEST(connectionToServerIsRemovedAfterIdleTimeoutTriggers),
            });

} // namespace
} // namespace flexisip::tester::sofia_tester_suite