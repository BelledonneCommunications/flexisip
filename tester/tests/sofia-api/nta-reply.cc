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

#include <memory>

#include "sofia-sip/msg.h"
#include "sofia-sip/nta.h"
#include "sofia-sip/nta_stateless.h"
#include "sofia-sip/sip_status.h"

#include "flexisip/sofia-wrapper/su-root.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/nta-outgoing-transaction.hh"
#include "utils/asserts.hh"
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

namespace timerC {

using AssertCallback = function<AssertionResult(const shared_ptr<NtaOutgoingTransaction>&, nta_agent_t*)>;

struct AgentState {
	using Callback = function<int(AgentState*, nta_agent_t*, msg_t*, sip_t*)>;

	nta_incoming_t* incoming{nullptr};
	nta_outgoing_t* outgoing{nullptr};
	Callback callback{};
	string targetUri{};
};

// This callback only reflects the callee response so we can test the status code at the transaction level in the
// assertion callback.
const auto forwardCalleeResponse = [](nta_outgoing_magic_t* magic, nta_outgoing_t*, const sip_t* sip) {
	if (sip && sip->sip_status) {
		auto* state = reinterpret_cast<AgentState*>(magic);
		nta_incoming_treply(state->incoming, sip->sip_status->st_status, "Stub phrase", TAG_END());
	}
	return 0;
};

// Forwards the CANCEL received from the caller to the callee.
const auto forwardCallerCancel = [](nta_incoming_magic_t* imagic, nta_incoming_t*, sip_t const* sip) {
	if (sip && sip->sip_request && sip->sip_request->rq_method == sip_method_cancel) {
		auto* state = reinterpret_cast<AgentState*>(imagic);
		nta_outgoing_tcancel(state->outgoing, nullptr, nullptr, NTATAG_CANCEL_3261(1), TAG_END());
	}
	return 0;
};

/**
 * Test template for timer C expiration.
 */
template <const bool cancel>
void timerCExpiration(const AgentState::Callback& calleeCallback, const AssertCallback& assertionCallback) {
	const auto suRoot = make_shared<SuRoot>();

	NtaAgent caller{suRoot, "sip:caller@127.0.0.2:0;transport=tcp"};
	const string callerUri{"sip:caller@sip.example.org"};

	AgentState calleeState{.callback = calleeCallback};
	const auto calleeCb = [](nta_agent_magic_t* magic, nta_agent_t* agent, msg_t* msg, sip_t* sip) {
		BC_HARD_ASSERT(magic != nullptr);
		auto* state = reinterpret_cast<AgentState*>(magic);
		return state->callback(state, agent, msg, sip);
	};
	auto* calleeStatePtr = reinterpret_cast<nta_agent_magic_t*>(&calleeState);
	NtaAgent callee{suRoot, "sip:callee@127.0.0.3:0;transport=tcp", calleeCb, calleeStatePtr};
	const auto calleeUri = getNtaAgentFirstTransport(callee);

	AgentState serverState{
	    .callback = [](AgentState* state, nta_agent_t* agent, msg_t* msg, sip_t*) -> int {
		    if (state->incoming == nullptr) {
			    state->incoming = nta_incoming_create(agent, nullptr, msg_ref(msg), sip_object(msg), TAG_END());
			    nta_incoming_treply(state->incoming, SIP_100_TRYING, TAG_END());
			    if constexpr (cancel)
				    nta_incoming_bind(state->incoming, forwardCallerCancel,
				                      reinterpret_cast<nta_incoming_magic_t*>(state));
		    }
		    if (state->outgoing == nullptr) {
			    auto* uri = toSofiaSipUrlUnion(state->targetUri);
			    auto* magic = reinterpret_cast<nta_outgoing_magic_t*>(state);
			    state->outgoing = nta_outgoing_mcreate(agent, forwardCalleeResponse, magic, uri, msg, TAG_END());
		    }
		    return 0;
	    },
	    .targetUri = calleeUri,
	};
	const auto serverCb = [](nta_agent_magic_t* magic, nta_agent_t* agent, msg_t* msg, sip_t* sip) -> int {
		BC_HARD_ASSERT(magic != nullptr);
		auto* state = reinterpret_cast<AgentState*>(magic);
		return state->callback(state, agent, msg, sip);
	};
	auto* serverStatePtr = reinterpret_cast<nta_agent_magic_t*>(&serverState);
	NtaAgent server{suRoot, "sip:127.0.0.1:0;transport=tcp", serverCb, serverStatePtr, NTATAG_TIMER_C(500)};

	stringstream rawInvite{};
	rawInvite << "INVITE " << calleeUri << " SIP/2.0\r\n"
	          << "Via: SIP/2.0/TCP 127.0.0.1:53314;branch=z9hG4bK.B7fbFxUnN;rport=53314;received=127.0.0.1\r\n"
	          << "From: <" << callerUri << ">;tag=stub-from-tag\r\n"
	          << "To: <" << calleeUri << ">\r\n"
	          << "Call-ID: stub-call-id\r\n"
	          << "CSeq: 20 INVITE\r\n"
	          << "Contact: <" << callerUri << ">\r\n"
	          << "Content-Length: 0\r\n\r\n";

	MsgSip inviteMsg{0, rawInvite.str()};
	const auto invTrans = caller.createOutgoingTransaction(inviteMsg.msgAsString(), getNtaAgentFirstTransport(server));

	CoreAssert asserter{suRoot};
	asserter.wait([&] { return LOOP_ASSERTION(invTrans->getStatus() == 180); }).assert_passed();

	if constexpr (cancel) invTrans->cancel();

	asserter.wait([&] { return assertionCallback(invTrans, server.getAgent()); }).assert_passed();
}

/**
 * Scenario:
 * 1. The caller sends an INVITE to the server.
 * 2. The server creates an outgoing transaction to the callee and forwards the INVITE.
 * 3. The callee replies to the INVITE with a provisional response (180).
 * 4. The server forwards the provisional response to the caller.
 * 5. Timer C expires, the server cancels the transaction towards the callee (and resets timer C).
 * 6. The callee replies to the CANCEL with a 200 OK and to the INVITE with a 487 Request Terminated.
 * 7. The server forwards the 487 response to the caller.
 * 8. The caller receives the 487 response and the transaction is completed with a final status of 487.
 */
void expirationCalleeResponsive() {
	const auto calleeCallback = [&](AgentState* state, nta_agent_t* agent, msg_t* msg, sip_t*) -> int {
		if (state->incoming != nullptr) {
			// Handle receipt of ACK.
			msg_destroy(msg);
			return 0;
		}

		// It is important the callee provides a provisional response (so the client transaction on the proxy goes in
		// the "proceeding" state).
		// Also, we create an incoming transaction so the callee will properly answer to the CANCEL request (200 Ok) and
		// the associated INVITE request (487 Request Terminated).
		state->incoming = nta_incoming_create(agent, nullptr, msg, sip_object(msg), TAG_END());
		nta_incoming_treply(state->incoming, SIP_180_RINGING, TAG_END());
		return 0;
	};

	const auto assertionCallback = [&](const shared_ptr<NtaOutgoingTransaction>& invite, nta_agent_t*) {
		FAIL_IF(invite->isCompleted() == false);
		FAIL_IF(invite->getStatus() != 487);
		return ASSERTION_PASSED();
	};

	timerCExpiration<false>(calleeCallback, assertionCallback);
}

/**
 * Scenario:
 * 1. The caller sends an INVITE to the server.
 * 2. The server creates an outgoing transaction to the callee and forwards the INVITE.
 * 3. The callee replies to the INVITE with a provisional response (180).
 * 4. The server forwards the provisional response to the caller.
 * 5. Timer C expires, the server cancels the transaction towards the callee (and resets timer C).
 * 6. The callee replies to the CANCEL with a 200 OK but does not reply to the INVITE.
 * 7. Timer C expires again, the server generates a 408 Request Timeout on callee's transaction (forwarded to the
 *    caller) and terminates the transaction.
 * 8. The caller receives the 408 response and the transaction is completed with a final status of 408.
 */
void expirationCalleeHalfResponsiveCancel() {
	bool receivedCancel{};

	const auto calleeCallback = [&](AgentState*, nta_agent_t* agent, msg_t* msg, sip_t* sip) -> int {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			receivedCancel = true;
			nta_msg_treply(agent, msg, SIP_200_OK, TAG_END());
			return 0;
		}
		// It is important the callee provides a provisional response (so the client transaction on the proxy goes in
		// the "proceeding" state).
		if (sip->sip_request->rq_method == sip_method_invite) nta_msg_treply(agent, msg, SIP_180_RINGING, TAG_END());
		return 0;
	};

	usize_t timeouts{};
	const auto assertionCallback = [&](const shared_ptr<NtaOutgoingTransaction>& invite, nta_agent_t* agent) {
		FAIL_IF(receivedCancel == false);
		FAIL_IF(invite->isCompleted() == false);
		FAIL_IF(invite->getStatus() != 408);

		// We expect a timeout on the outgoing transaction to the callee.
		nta_agent_get_stats(agent, NTATAG_S_TOUT_REQUEST_REF(timeouts), TAG_END());
		FAIL_IF(timeouts != 1);
		return ASSERTION_PASSED();
	};

	timerCExpiration<false>(calleeCallback, assertionCallback);
}

/**
 * Scenario:
 * 1. The caller sends an INVITE to the server.
 * 2. The server creates an outgoing transaction to the callee and forwards the INVITE.
 * 3. The callee replies to the INVITE with a provisional response (180).
 * 4. Timer C expires, the server cancels the transaction towards the callee (and resets timer C).
 * 5. The callee receives the CANCEL but does not reply to it or to the INVITE.
 * 6. Timer C expires again, the server generates a 408 Request Timeout on callee's transaction (forwarded to the
 *    caller) and terminates the transaction.
 * 7. The caller receives the 408 response and the transaction is completed with a final status of 408.
 */
void expirationCalleeNonResponsive() {
	bool receivedCancel{};

	const auto calleeCallback = [&](AgentState*, nta_agent_t* agent, msg_t* msg, sip_t* sip) -> int {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			receivedCancel = true;
			// Simulate an unresponsive callee by not replying to CANCEL.
			msg_destroy(msg);
			return 0;
		}
		// It is important the callee provides a provisional response (so the client transaction on the proxy goes in
		// the "proceeding" state).
		if (sip->sip_request->rq_method == sip_method_invite) nta_msg_treply(agent, msg, SIP_180_RINGING, TAG_END());
		return 0;
	};

	usize_t timeouts{};
	const auto assertionCallback = [&](const shared_ptr<NtaOutgoingTransaction>& invite, nta_agent_t* agent) {
		FAIL_IF(receivedCancel == false);
		FAIL_IF(invite->isCompleted() == false);
		FAIL_IF(invite->getStatus() != 408);

		// We expect a timeout on the outgoing transaction to the callee.
		nta_agent_get_stats(agent, NTATAG_S_TOUT_REQUEST_REF(timeouts), TAG_END());
		FAIL_IF(timeouts != 1);
		return ASSERTION_PASSED();
	};

	timerCExpiration<false>(calleeCallback, assertionCallback);
}

/**
 * Scenario:
 * 1. The caller sends an INVITE to the server.
 * 2. The server creates an outgoing transaction to the callee and forwards the INVITE.
 * 3. The callee replies to the INVITE with a provisional response (180).
 * 4. The caller CANCELs the INVITE before timer C expiration.
 * 5. The callee receives the CANCEL but does not reply to it or to the INVITE.
 * 6. Timer C expires, the server generates a 408 Request Timeout on callee's transaction (forwarded to the caller) and
 *    terminates the transaction.
 * 7. The caller receives the 408 response and the transaction is completed with a final status of 408.
 */
void expirationCalleeNonResponsiveWithCancel() {
	bool receivedCancel{};

	const auto calleeCallback = [&](AgentState*, nta_agent_t* agent, msg_t* msg, sip_t* sip) -> int {
		if (sip->sip_request->rq_method == sip_method_cancel) {
			receivedCancel = true;
			// Simulate an unresponsive callee by not replying to CANCEL.
			msg_destroy(msg);
			return 0;
		}
		// It is important the callee provides a provisional response (so the client transaction on the proxy goes in
		// the "proceeding" state).
		if (sip->sip_request->rq_method == sip_method_invite) nta_msg_treply(agent, msg, SIP_180_RINGING, TAG_END());
		return 0;
	};

	usize_t timeouts{};
	const auto assertionCallback = [&](const shared_ptr<NtaOutgoingTransaction>& invite, nta_agent_t* agent) {
		FAIL_IF(receivedCancel == false);
		FAIL_IF(invite->isCompleted() == false);
		FAIL_IF(invite->getStatus() != 487);

		// We still expect a timeout on the outgoing transaction to the callee.
		nta_agent_get_stats(agent, NTATAG_S_TOUT_REQUEST_REF(timeouts), TAG_END());
		FAIL_IF(timeouts != 1);
		return ASSERTION_PASSED();
	};

	timerCExpiration<true>(calleeCallback, assertionCallback);
}

} // namespace timerC

TestSuite _{
    "sofia::nta::reply",
    {
        CLASSY_TEST(incomingReply),
        CLASSY_TEST(timerC::expirationCalleeResponsive),
        CLASSY_TEST(timerC::expirationCalleeHalfResponsiveCancel),
        CLASSY_TEST(timerC::expirationCalleeNonResponsive),
        CLASSY_TEST(timerC::expirationCalleeNonResponsiveWithCancel),
    },
};

} // namespace
} // namespace flexisip::tester::sofia_tester_suite