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

#include "flexisip/sofia-wrapper/su-root.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "tester.hh"
#include "utils/client-builder.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
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

/**
 * Test primary transport selection to reach a destination using the 'network' URI parameter.
 * Verifies that the most appropriate transport is selected to reach the destination.
 * This test also verifies that the right "RecordRoute" header was inserted by the Proxy when the request arrives to the
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
 *     -------------       /            \       --------------
 *    |   Flexisip  | --- | 127.0.1.0/24 | --- | localClient2 |
 *     -------------       \            /       --------------
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
	const string publicTport{"sip:" + publicTportHost + ":0;maddr=127.1.0.1;transport=tcp"};
	const string localTport2{"sip:" + localTport2Host + ":0;transport=tcp;network=127.0.1.0/24,127.0.2.0/24"};
	Server proxy{{
	    {"global/transports", localTport1 + " " + publicTport + " " + localTport2},
	    {"global/aliases", "sip.example.org"},
	    {"module::DoSProtection/enabled", "false"},
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
		auto* helper = reinterpret_cast<Helper*>(magic);
		// The topmost "RecordRoute" header in the list is the last one added by the server.
		const auto* recordRoute = sip->sip_record_route->r_url;

		helper->host = sip->sip_via->v_host;
		helper->recordRoute = "sip:"s + recordRoute->url_host + ":" + recordRoute->url_port;

		nta_msg_treply(agent, msg, 202, "Accepted", TAG_END());
		return 0;
	};
	NtaAgent publicClient{clientsSuRoot, "sip:127.1.0.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};
	NtaAgent localClient1{clientsSuRoot, "sip:127.0.0.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};
	NtaAgent localClient2{clientsSuRoot, "sip:127.0.1.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};
	NtaAgent localClient3{clientsSuRoot, "sip:127.0.2.2:0;transport=tcp", cb, reinterpret_cast<nta_agent_magic_t*>(&h)};

	CoreAssert<kNoSleep> asserter{proxy, clientsSuRoot};

	const auto test = [&proxy, &asserter, &h](NtaAgent& caller, const NtaAgent& callee, const string& expectedHostInVia,
	                                          const string& expectedRecordRoute) {
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_invite, getNtaAgentFirstTransport(callee));
		request->makeAndInsert<SipHeaderFrom>("sip:caller@sip.example.org", "stub-from-tag");
		request->makeAndInsert<SipHeaderTo>("sip:callee@sip.example.org");
		request->makeAndInsert<SipHeaderCallID>("stub-call-id");
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_invite);
		request->makeAndInsert<SipHeaderContact>("<sip:caller@sip.example.org;transport=tcp>");

		const auto routeUri = "sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp";

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
	};

	auto* primary = tport_primaries(nta_agent_tports(proxy.getAgent()->getSofiaAgent()));
	const string realLocalTport1{"sip:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};
	primary = tport_next(primary);
	const string realPublicTport{"sip:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};
	primary = tport_next(primary);
	const string realLocalTport2{"sip:"s + tport_name(primary)->tpn_canon + ":" + tport_name(primary)->tpn_port};

	test(publicClient, localClient1, localTport1Host, realLocalTport1);
	test(publicClient, localClient2, localTport2Host, realLocalTport2);
	test(publicClient, localClient3, localTport2Host, realLocalTport2);
	test(localClient1, publicClient, publicTportHost, realPublicTport);
	test(localClient1, localClient2, localTport2Host, realLocalTport2);
	test(localClient1, localClient3, localTport2Host, realLocalTport2);
	test(localClient2, publicClient, publicTportHost, realPublicTport);
	test(localClient2, localClient1, localTport1Host, realLocalTport1);
	test(localClient2, localClient3, localTport2Host, realLocalTport2);
	test(localClient3, publicClient, publicTportHost, realPublicTport);
	test(localClient3, localClient1, localTport1Host, realLocalTport1);
	test(localClient3, localClient2, localTport2Host, realLocalTport2);
}

TestSuite _{
    "sofia::nta::reply",
    {
        CLASSY_TEST(outgoingTransportSelection),
    },
};
} // namespace
} // namespace flexisip::tester::sofia_tester_suite