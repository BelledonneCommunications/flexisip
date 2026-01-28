/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

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
		nta_outgoing_mcreate(agent, nullptr, nullptr, toSofiaSipUrlUnion(calleeUri), msg, TAG_END());
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
        CLASSY_TEST(incomingReply),
        CLASSY_TEST(cancelOnTimerCWithProvisionalResponse),
    },
};

} // namespace
} // namespace flexisip::tester::sofia_tester_suite