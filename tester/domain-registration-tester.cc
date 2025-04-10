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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <chrono>
#include <string>

#include "domain-registrations.hh"
#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/rand.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {

template <bool useTls>
void RFC5626ReconnectOnPongTimeout() {
	constexpr auto keepAliveInterval = 2s;
	constexpr auto pingPongTimoutDelay = 1s;
	constexpr auto localDomain = "local.sip.example.org";
	const auto logSep = string(45, '=');
	const auto certFilePath = bcTesterRes("cert/self.signed.cert.test.pem");
	const auto keyFilePath = bcTesterRes("cert/self.signed.key.test.pem");

	Server local{{
	    {"global/transports", useTls ? "sips:127.0.0.1:0;tls-verify-outgoing=0" : "sip:127.0.0.1:0;transport=tcp"},
	    {"inter-domain-connections/keepalive-interval", to_string(keepAliveInterval.count())},
	    {"inter-domain-connections/ping-pong-timeout-delay", to_string(pingPongTimoutDelay.count())},
	    {"inter-domain-connections/reconnection-delay", "0"},
	}};
	if constexpr (useTls) {
		local.setConfigParameter({"global/tls-certificates-file", certFilePath});
		local.setConfigParameter({"global/tls-certificates-private-key", keyFilePath});
	}
	local.start();

	Server remote{{
	    {"global/transports", useTls ? "sips:127.0.0.1:0;tls-verify-outgoing=0" : "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "*.sip.example.org"},
	    {"inter-domain-connections/accept-domain-registrations", "true"},
	}};
	if constexpr (useTls) {
		remote.setConfigParameter({"global/tls-certificates-file", certFilePath});
		remote.setConfigParameter({"global/tls-certificates-private-key", keyFilePath});
	}
	remote.start();
	sofiasip::Url remoteUri{"sip:127.0.0.1:"s + remote.getFirstPort() + ";transport=" + (useTls ? "tls" : "tcp")};

	CoreAssert asserter{local, remote};

	auto* drm = local.getAgent()->getDRM();
	auto reg = make_shared<DomainRegistration>(*drm, localDomain, remoteUri, "", sofiasip::TlsConfigInfo{}, "", 0);
	drm->addDomainRegistration(reg);

	SLOGD << logSep << " Starting domain registration " << logSep;
	reg->start();
	asserter.iterateUpTo(
	            128, [&drm]() { return LOOP_ASSERTION(drm->getRegistrationCount() == 1); }, 1s)
	    .hard_assert_passed();

	SLOGD << logSep << " Waiting for several PING sendings " << logSep;
	// Check that the connection hasn't been broken for the last seconds.
	const auto timeout = duration_cast<milliseconds>(2 * keepAliveInterval * 1.05);
	const auto end = system_clock::now() + timeout;
	while (system_clock::now() <= end) {
		asserter.iterateAllOnce();
		BC_HARD_ASSERT(reg->getRegistrationStatus()->read() == 200);
		std::this_thread::sleep_for(kDefaultSleepInterval);
	}

	SLOGD << logSep << " Pausing the remote proxy in order to simulate a network problem " << logSep;
	const auto timeout2 = duration_cast<milliseconds>((keepAliveInterval + pingPongTimoutDelay) * 1.05);
	CoreAssert{local}
	    .iterateUpTo(
	        128, [&reg]() { return LOOP_ASSERTION(reg->getRegistrationStatus()->read() == 503); }, timeout2)
	    .hard_assert_passed();

	SLOGD << logSep << " Resume the remote proxy and wait for a new successful registration " << logSep;
	asserter.iterateUpTo(
	            128, [&reg]() { return LOOP_ASSERTION(reg->getRegistrationStatus()->read() == 200); }, 1s)
	    .hard_assert_passed();

	SLOGD << logSep << " Stopping domain registration " << logSep;
	reg->stop();
	asserter.iterateUpTo(
	            128, [&drm]() { return LOOP_ASSERTION(drm->getRegistrationCount() == 0); }, 1s)
	    .assert_passed();
}

namespace {

TestSuite _{
    "DomainRegistration",
    {
        CLASSY_TEST(RFC5626ReconnectOnPongTimeout<false>),
        CLASSY_TEST(RFC5626ReconnectOnPongTimeout<true>),
    },
};

}
} // namespace flexisip::tester