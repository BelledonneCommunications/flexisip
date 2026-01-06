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

#include <string>

#include "sofia-wrapper/nta-agent.hh"
#include "tester.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
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

/*
 * Register a client at home which may be a doorbell and another one outside.
 * Ensure that calls may be established both ways.
 *
 * It checks:
 *  - domain-registrations on client and remote sides
 *  - reg-on-response
 *  - Record-Route insertion in the domain registration case
 *  - TLS client transport
 */
void localAndPublicProxies() {
	auto root = make_shared<sofiasip::SuRoot>();
	RedisServer redis{};
	const string domain = "sip.example.org";
	const auto certFilePath = bcTesterRes("cert/self.signed.cert.test.pem");
	const auto keyFilePath = bcTesterRes("cert/self.signed.key.test.pem");

	Server cloudProxy({
	    {"global/transports", "sips:127.0.0.1:0"},
	    {"global/tls-certificates-file", certFilePath},
	    {"global/tls-certificates-private-key", keyFilePath},
	    {"inter-domain-connections/accept-domain-registrations", "true"},
	    {"inter-domain-connections/relay-reg-to-domains", "true"},
	    {"inter-domain-connections/relay-reg-to-domains-regex", domain},
	    {"module::Registrar/reg-domains", "*"},
	    {"module::Registrar/enable-gruu", "true"},
	    {"module::Registrar/reg-on-response", "true"},
	    {"module::DoSProtection/enabled", "false"},
	});
	cloudProxy.start();

	TempFile domainFile(domain + " <sips:127.0.0.1:"s + cloudProxy.getFirstPort() + ">\n");

	Server homeProxy{
	    {
	        {"global/transports", "sip:127.0.0.1:0 sips:127.0.0.1:0;tls-client-connection=1;tls-verify-outgoing=0"},
	        {"inter-domain-connections/domain-registrations", domainFile.getFilename()},
	        {"module::Registrar/reg-domains", domain},
	        {"module::Registrar/enable-gruu", "true"},
	        {"module::Registrar/db-implementation", "redis"},
	        {"module::Registrar/redis-server-domain", "localhost"},
	        {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	        {"module::DoSProtection/enabled", "false"},
	    },
	    // Use same root in order to iterate both proxies when un-registering
	    cloudProxy.getRoot(),
	};
	homeProxy.start();

	ClientBuilder homeBuilder{*homeProxy.getAgent()};
	ClientBuilder cloudBuilder{*cloudProxy.getAgent()};
	auto homeClient = homeBuilder.build("sip:home@sip.example.org");
	auto cloudClient = cloudBuilder.build("sip:remote@sip.example.org;transport=tls");
	CoreAssert asserter{cloudProxy, homeProxy, homeClient, cloudClient};

	{
		auto homeCall = homeClient.call(cloudClient, cloudClient.getCore()->createAddress("sip:remote@sip.example.org"),
		                                nullptr, nullptr, {}, cloudProxy.getAgent());
		auto cloudClientCall = cloudClient.getCurrentCall();

		ASSERT_PASSED(asserter.iterateUpTo(
		    50, [&cloudClientCall] { return cloudClientCall->getState() == linphone::Call::State::StreamsRunning; },
		    1s));

		BC_ASSERT_CPP_EQUAL(cloudClientCall->terminate(), 0);
		ASSERT_PASSED(asserter.iterateUpTo(
		    5,
		    [&cloudClientCall, &homeCall] {
			    FAIL_IF(homeCall->getState() != linphone::Call::State::End);
			    return LOOP_ASSERTION(cloudClientCall->getState() == linphone::Call::State::End);
		    },
		    1s));
	}

	{
		auto cloudClientCall =
		    cloudClient.call(homeClient, homeClient.getCore()->createAddress("sip:home@sip.example.org"), nullptr,
		                     nullptr, {}, homeProxy.getAgent());
		auto homeClientCall = homeClient.getCurrentCall();

		ASSERT_PASSED(asserter.iterateUpTo(
		    50, [&homeClientCall] { return homeClientCall->getState() == linphone::Call::State::StreamsRunning; }, 1s));

		BC_ASSERT_CPP_EQUAL(homeClientCall->terminate(), 0);
		ASSERT_PASSED(asserter.iterateUpTo(
		    5,
		    [&homeClientCall, &cloudClientCall] {
			    FAIL_IF(cloudClientCall->getState() != linphone::Call::State::End);
			    return LOOP_ASSERTION(homeClientCall->getState() == linphone::Call::State::End);
		    },
		    1s));
	}
}

TestSuite _("Domotic",
            {
                CLASSY_TEST(localAndPublicProxies),
            });
} // namespace
} // namespace flexisip::tester