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

#include "sofia-wrapper/nta-agent.hh"
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

/*
 * 2-proxies scenario:
 * A local (home) proxy is responsible for device registration and call management.
 * A public (cloud) proxy is used to add push notifications (PN). It uses the 'reg-on-response' feature to register data
 * relating to mobile devices.
 *
 * When the home proxy receives an INVITE from the doorbell, it creates a ForkCallCtx with one branch per device.
 * Then, the cloud proxy receives each mobile INVITE independently and creates a one-branch ForkCallCtx for each device.
 *
 *    Bell           HomeProxy          House          CloudProxy         Mobile1          Mobile2
 *      |                |                |                |                |                |
 *      | -------------> |                |                |                |                |
 *                       | -------------> |                |                |                |
 *                       | ------------------------------> |                |                |
 *                       |                                 | -------------> |                |
 *                       | ------------------------------> |                                 |
 *                       |                                 | ------------------------------> |
 */

// REGISTER a mobile user and check that a doorbell INVITE is corretly sent to the user
void localAndPublicProxies() {
	RedisServer redis{};
	const string domain = "sip.example.org";

	Server cloudProxy({
	    {"inter-domain-connections/accept-domain-registrations", "true"},
	    {"inter-domain-connections/relay-reg-to-domains", "true"},
	    {"inter-domain-connections/relay-reg-to-domains-regex", domain},
	    {"module::Registrar/reg-domains", "*"},
	    {"module::Registrar/enable-gruu", "true"},
	    {"module::Registrar/reg-on-response", "true"},
	    {"module::DoSProtection/enabled", "false"},
	});
	cloudProxy.start();

	TempFile domainFile(domain + " <sip:127.0.0.1:"s + cloudProxy.getFirstPort() + ">\n");
	Server homeProxy({
	    {"inter-domain-connections/domain-registrations", domainFile.getFilename()},
	    {"module::Registrar/reg-domains", domain},
	    {"module::Registrar/enable-gruu", "true"},
	    {"module::Registrar/db-implementation", "redis"},
	    {"module::Registrar/redis-server-domain", "localhost"},
	    {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	    {"module::DoSProtection/enabled", "false"},
	});
	homeProxy.start();

	CoreAssert asserter{cloudProxy, homeProxy};

	const string sipUri("sip:user@" + domain);
	const string gruu = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";

	{
		// clang-format off
		const std::string registerRequest(
			"REGISTER sip:" + domain + " SIP/2.0\r\n"
			"From: <" + sipUri + ">;tag=465687829\r\n"
			"To: <" + sipUri + ">\r\n"
			"Call-ID: 1053183492" + "\r\n"
			"CSeq: 20 REGISTER\r\n"
			"Contact: <sip:user@127.0.0.1;>;+sip.instance=\"<" + gruu + ">\"\r\n"
			"Supported: gruu\r\n"
			"Expires: 600\r\n"
			"Content-Length: 0\r\n\r\n");
		// clang-format on

		sofiasip::NtaAgent client{cloudProxy.getRoot(), "sip:127.0.0.1:0"};
		auto transaction =
		    client.createOutgoingTransaction(registerRequest, "sip:127.0.0.1:"s + cloudProxy.getFirstPort());

		BC_ASSERT_TRUE(asserter.iterateUpTo(5, [&transaction] { return transaction->isCompleted(); }, 2s));

		auto response = transaction->getResponse();
		BC_HARD_ASSERT(response != nullptr);

		const auto rawResponse = response->msgAsString();
		SLOGD << "Server response:\n" << rawResponse;
		BC_HARD_ASSERT(transaction->getStatus() == 200);
	}

	{

		const string bell("sip:bell@" + domain);
		// clang-format off
		string request(
		    "INVITE "s + sipUri + " SIP/2.0\r\n"
			"Max-Forwards: 5\r\n"
			"To: user <" + sipUri + ">\r\n"
			"From: bell <" + bell + ">;tag=465687829\r\n"
			"Call-ID: 1053183492\r\n"
			"CSeq: 10 INVITE\r\n"
			"Contact: <" + bell + ";transport=tcp>\r\n"
			"Supported: gruu\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: 0\r\n");
		// clang-format on
		sofiasip::NtaAgent client{homeProxy.getRoot(), "sip:127.0.0.1:0"};
		auto transaction = client.createOutgoingTransaction(request, "sip:127.0.0.1:"s + homeProxy.getFirstPort());
		BC_ASSERT_TRUE(asserter.iterateUpTo(5, [&transaction] { return transaction->isCompleted(); }, 2s));

		auto response = transaction->getResponse();
		BC_HARD_ASSERT(response != nullptr);

		const auto rawResponse = response->msgAsString();
		SLOGD << "Server response:\n" << rawResponse;
		BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 503);
	}
}
TestSuite _("Domotic",
            {
                CLASSY_TEST(localAndPublicProxies),
            });
} // namespace
} // namespace flexisip::tester