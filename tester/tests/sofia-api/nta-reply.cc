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

#include "sofia-sip/nta.h"
#include "sofia-sip/nta_stateless.h"
#include "sofia-sip/sip_status.h"

#include "flexisip/sofia-wrapper/su-root.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "tester.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tls/certificate.hh"
#include "utils/tls/private-key.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester::sofia_tester_suite {
namespace {

/**
 * @return first transport in the following format: "sip:host:port;maddr=xxx;transport=xxx" or empty string if no
 * transport were found.
 */
std::string getNtaAgentFirstTransport(const NtaAgent& agent) {
	const auto* firstTport = tport_primaries(agent.getTransports());
	if (!firstTport) return {};

	const auto* name = tport_name(firstTport);
	return std::string{"sip:"} + name->tpn_canon + ":" + name->tpn_port + ";maddr=" + name->tpn_host +
	       ";transport=" + name->tpn_proto;
}

/**
 * Test primary transport selection to reach a destination using the 'network' URI parameter.
 * Verifies that the most appropriate transport is selected to reach the destination.
 * This test also verifies that the Proxy inserted the right "RecordRoute" header when the request arrives to the
 * callee.
 *
 * Configuration:
 *                           ----------
 *     --------------      /            \       --------------
 *    | localClient1 |    | 127.0.2.0/24 | --- | localClient3 |
 *     --------------      \            /       --------------
 *           |               ----------
 *       ----------              |
 *     /            \         --------
 *    | 127.0.0.0/24 |       | router |
 *     \            /         --------
 *       ----------              |
 *           |               ----------
 *     -------------       /            \       ---------------------
 *    |   Flexisip  | --- | 127.0.1.0/24 | --- | localClient2 (sips) |
 *     -------------       \            /       --------------------
 *           |               ----------
 *       ----------
 *     /            \       --------------
 *    |   0.0.0.0/0  | --- | publicClient |
 *     \            /       --------------
 *       ----------
 */
void outgoingTransportSelection() {
	const string localTport1Host{"127.0.0.1"};
	const string publicTportHost{"sip.example.org"};
	const string localTport2Host{"127.0.1.1"};
	const string localTport1{"sip:" + localTport1Host + ":0;transport=tcp;network=127.0.0.0/24"};
	const string publicTportTcp{"sip:" + publicTportHost + ":0;maddr=127.1.0.1;transport=tcp"};
	const string publicTportTls{"sips:" + publicTportHost + ":0;maddr=127.1.0.1;tls-verify-outgoing=0"};
	const string localTport2Tcp{"sip:" + localTport2Host + ":0;network=127.0.1.0/24,127.0.2.0/24"};
	const string localTport2Tls{"sips:" + localTport2Host +
	                            ":0;tls-verify-outgoing=0;network=127.0.1.0/24,127.0.2.0/24"};

	// Server certificates.
	auto dir = TmpDir("certs-");
	const auto keyPath = dir.path() / "key.pem";
	const auto certPath = dir.path() / "cert.pem";
	const TlsPrivateKey privateKey{};
	const TlsCertificate certificate{privateKey};
	privateKey.writeToFile(keyPath);
	certificate.writeToFile(certPath);

	// Client certificate.
	const auto certs = bcTesterRes("cert/self.signed.legacy");

	Server proxy{{
	    {"global/transports",
	     localTport1 + " " + publicTportTcp + " " + publicTportTls + " " + localTport2Tls + " " + localTport2Tcp},
	    {"global/aliases", "sip.example.org"},
	    {"global/tls-certificates-file", certPath},
	    {"global/tls-certificates-private-key", keyPath},
	    {"module::DoSProtection/enabled", "false"},
	    {"module::MediaRelay/enabled", "false"},
	}};
	proxy.start();

	struct Helper {
		string host{};
		string recordRoute{};
	};
	Helper h{};

	const auto clientsSuRoot = make_shared<SuRoot>();
	const auto cb = [](nta_agent_magic_t* magic, nta_agent_t* agent, msg_t* msg, sip_t* sip) -> int {
		Home home{};

		SLOGD << "Received:\n" << msg_as_string(home.home(), msg, nullptr, 0, nullptr);

		auto* helper = reinterpret_cast<Helper*>(magic);
		// The topmost "RecordRoute" header in the list is the last one added by the server.
		const auto* recordRoute = sip->sip_record_route->r_url;

		helper->host = sip->sip_via->v_host;
		helper->recordRoute = recordRoute->url_scheme + ":"s + recordRoute->url_host + ":" + recordRoute->url_port;

		nta_msg_treply(agent, msg, 202, "Accepted", TAG_END());
		return 0;
	};
	NtaAgent publicClient{clientsSuRoot, "sip:127.1.0.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};
	NtaAgent localClient1{clientsSuRoot, "sip:127.0.0.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};
	NtaAgent localClient2{
	    clientsSuRoot,
	    "sips:127.0.1.2:0",
	    cb,
	    reinterpret_cast<nta_agent_magic_t*>(&h),
	    TPTAG_CERTIFICATE(certs.c_str()),
	    TPTAG_CERTIFICATE_CA_FILE(""),
	    TPTAG_TLS_VERIFY_POLICY(TPTLS_VERIFY_NONE),
	    TPTAG_TLS_CIPHERS("HIGH:!SSLv2:!SSLv3:!TLSv1:!EXP:!ADH:!RC4:!3DES:!aNULL:!eNULL"),
	};
	NtaAgent localClient3{clientsSuRoot, "sip:127.0.2.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};

	auto* primary = tport_primaries(nta_agent_tports(proxy.getAgent()->getSofiaAgent()));
	const string realLocalTport1{"sip:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};
	primary = tport_next(primary);
	const string realPublicTport{"sip:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};
	primary = tport_next(tport_next(primary)); // Skip tls public transport.
	const string realLocalTport2Tls{"sips:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};
	primary = tport_next(primary);
	const string realLocalTport2Tcp{"sip:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};

	CoreAssert<kNoSleep> asserter{proxy, clientsSuRoot};

	const auto test = [&](NtaAgent& caller, const NtaAgent& callee, const string& expectedHostInVia,
	                      const string& expectedRecordRoute) {
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_invite, getNtaAgentFirstTransport(callee));
		request->makeAndInsert<SipHeaderFrom>("sip:caller@sip.example.org", "stub-from-tag");
		request->makeAndInsert<SipHeaderTo>("sip:callee@sip.example.org");
		request->makeAndInsert<SipHeaderCallID>("stub-call-id");
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_invite);
		request->makeAndInsert<SipHeaderContact>("<sip:caller@sip.example.org;transport=tcp>");

		const auto routeUri = SipUri{getNtaAgentFirstTransport(caller)}.getParam("transport") == "tls"
		                          ? realLocalTport2Tls
		                          : realLocalTport1 + ";transport=tcp";
		const auto transaction = caller.createOutgoingTransaction(std::move(request), routeUri);

		asserter
		    .iterateUpTo(
		        0x20,
		        [&] {
			        FAIL_IF(!transaction->isCompleted());
			        FAIL_IF(expectedHostInVia != h.host);
			        FAIL_IF(expectedRecordRoute != h.recordRoute);
			        return ASSERTION_PASSED();
		        },
		        100ms)
		    .assert_passed();
		BC_ASSERT_CPP_EQUAL(h.host, expectedHostInVia);
		BC_ASSERT_CPP_EQUAL(h.recordRoute, expectedRecordRoute);

		h.host.clear();
		h.recordRoute.clear();
	};

	test(publicClient, localClient1, localTport1Host, realLocalTport1);
	test(publicClient, localClient2, localTport2Host, realLocalTport2Tls);
	test(publicClient, localClient3, localTport2Host, realLocalTport2Tcp);
	test(localClient1, publicClient, publicTportHost, realPublicTport);
	test(localClient1, localClient2, localTport2Host, realLocalTport2Tls);
	test(localClient1, localClient3, localTport2Host, realLocalTport2Tcp);
	test(localClient2, publicClient, publicTportHost, realPublicTport);
	test(localClient2, localClient1, localTport1Host, realLocalTport1);
	test(localClient2, localClient3, localTport2Host, realLocalTport2Tcp);
	test(localClient3, publicClient, publicTportHost, realPublicTport);
	test(localClient3, localClient1, localTport1Host, realLocalTport1);
	test(localClient3, localClient2, localTport2Host, realLocalTport2Tls);
}

/*
 * Test behavior of Sofia-SIP when replying to a message without tport set.
 * This case occurs when an incoming transaction is created after a request has been suspended (see tport_deliver).
 * After replying, all objects must be properly destroyed (no crash).
 */
void incomingReply() {
	const auto suRoot = make_shared<SuRoot>();
	NtaAgent server{suRoot, "sip:127.0.0.1:0;transport=tcp", nullptr, nullptr, TAG_END()};

	const string sipUri("sip:user@sip.example.org");
	stringstream rawRequest{};
	rawRequest << "REGISTER " << sipUri << " SIP/2.0\r\n"
	           << "Via: SIP/2.0/TCP 127.0.0.1:53314;branch=z9hG4bK.B7fbFxUnN;rport=53314;received=127.0.0.1\r\n"
	           << "From: <" << sipUri << ">;tag=465687829\r\n"
	           << "To: <" << sipUri << ">\r\n"
	           << "Call-ID: stub-call-id\r\n"
	           << "CSeq: 20 REGISTER\r\n"
	           << "Contact: <" << sipUri << ">\r\n"
	           << "Expires: 600\r\n"
	           << "Content-Length: 0\r\n\r\n";

	auto request = make_unique<MsgSip>(0, rawRequest.str());
	auto* msg = msg_ref_create(request->getMsg());

	auto* irq = nta_incoming_create(server.getAgent(), nullptr, msg, sip_object(msg), TAG_END());
	nta_incoming_treply(irq, SIP_200_OK, TAG_END());
}

/**
 * Test that on timer C expiration (RFC3261 16.6 11), a CANCEL request is sent (RFC3261 16.8) and the outgoing
 * transaction is properly transitioned to the "terminated" state.
 */
void cancelOnTimerCWithProvisionalResponse() {
	const auto suRoot = make_shared<SuRoot>();
	static bool receivedCancel{false};

	NtaAgent caller{suRoot, "sip:caller@127.0.0.2:0;transport=tcp"};
	const string callerUri{"sip:caller@sip.example.org"};

	const auto calleeCb = [](nta_agent_magic_t*, nta_agent_t* agent, msg_t* msg, sip_t* sip) {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			receivedCancel = true;
			nta_msg_treply(agent, msg, SIP_200_OK, TAG_END());
			return 0;
		}
		// It is important the callee provides a provisional response (so the client transaction on the proxy goes in
		// the "proceeding" state).
		if (sip->sip_request->rq_method == sip_method_invite) nta_msg_treply(agent, msg, SIP_100_TRYING, TAG_END());
		return 0;
	};
	NtaAgent callee{suRoot, "sip:callee@127.0.0.3:0;transport=tcp", calleeCb};
	static const auto calleeUri = getNtaAgentFirstTransport(callee);

	const auto serverCb = [](nta_agent_magic_t*, nta_agent_t* agent, msg_t* msg, sip_t*) -> int {
		auto* incoming = nta_incoming_create(agent, nullptr, msg_ref(msg), sip_object(msg), TAG_END());
		nta_incoming_treply(incoming, SIP_100_TRYING, TAG_END());
		nta_outgoing_mcreate(agent, {}, toSofiaSipUrlUnion(calleeUri), msg, TAG_END());
		return 0;
	};
	NtaAgent server{suRoot, "sip:127.0.0.1:0;transport=tcp", serverCb, nullptr, NTATAG_TIMER_C(500)};

	stringstream rawRequest{};
	rawRequest << "INVITE " << callerUri << " SIP/2.0\r\n"
	           << "Via: SIP/2.0/TCP 127.0.0.1:53314;branch=z9hG4bK.B7fbFxUnN;rport=53314;received=127.0.0.1\r\n"
	           << "From: <" << callerUri << ">;tag=465687829\r\n"
	           << "To: <" << callerUri << ">\r\n"
	           << "Call-ID: stub-call-id\r\n"
	           << "CSeq: 20 INVITE\r\n"
	           << "Contact: <" << callerUri << ">\r\n"
	           << "Expires: 600\r\n"
	           << "Content-Length: 0\r\n\r\n";

	MsgSip message{0, rawRequest.str()};
	const auto transaction = caller.createOutgoingTransaction(message.msgAsString(), getNtaAgentFirstTransport(server));

	usize_t terminatedQueueLength{};
	CoreAssert{suRoot}
	    .wait([&] {
		    FAIL_IF(receivedCancel == false);
		    nta_agent_get_stats(server.getAgent(), NTATAG_S_ORQ_Q_TERM_LEN_REF(terminatedQueueLength), TAG_END());
		    FAIL_IF(terminatedQueueLength != 1);
		    FAIL_IF(transaction->isCompleted() == true);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

TestSuite _{
    "sofia::nta::reply",
    {
        CLASSY_TEST(outgoingTransportSelection),
        CLASSY_TEST(incomingReply),
        CLASSY_TEST(cancelOnTimerCWithProvisionalResponse),
    },
};

} // namespace
} // namespace flexisip::tester::sofia_tester_suite