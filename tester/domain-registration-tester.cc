/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <chrono>
#include <map>
#include <stdexcept>
#include <string>

#include "domain-registrations.hh"
#include "utils/proxy-server-process.hh"
#include "utils/rand.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {

/**
 * This test depends of AgentTest although it doesn't test the agent directly because the DomainRegistration object
 * need a Registrar-proxy to work.
 */
class RFC5626ReconnectOnPongTimeoutBase : public AgentTest {
public:
	RFC5626ReconnectOnPongTimeoutBase(bool useTls) : AgentTest{true}, mUseTls{useTls} {
		mRemoteProxyPort = Rand::generate(1025, numeric_limits<uint16_t>::max());
		mRemoteProxyTransport = mUseTls ? "sips:127.0.0.1:" + to_string(mRemoteProxyPort)
		                                : "sip:127.0.0.1:" + to_string(mRemoteProxyPort) + ";transport=tcp";

		map<string, string> remoteProxyConfig{{"global/transports", mRemoteProxyTransport},
		                                      {"module::Registrar/enabled", "true"},
		                                      {"module::Registrar/reg-domains", "*.sip.example.org"},
		                                      {"inter-domain-connections/accept-domain-registrations", "true"}};
		if (mUseTls) {
			auto certfile =
			    static_cast<string>(bc_tester_get_resource_dir_prefix()) + "/cert/self.signed.cert.test.pem";
			auto keyfile = static_cast<string>(bc_tester_get_resource_dir_prefix()) + "/cert/self.signed.key.test.pem";
			remoteProxyConfig.emplace("global/tls-certificates-file", certfile);
			remoteProxyConfig.emplace("global/tls-certificates-private-key", keyfile);
		}
		SLOGD << "Spawning and starting remote proxy...";
		mRemoteProxy.spawn(remoteProxyConfig);
		SLOGD << "Remote proxy ready and listening on port " << mRemoteProxyPort;
	};

private:
	// Private methods
	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		auto localProxyPort = Rand::generate(1025, numeric_limits<uint16_t>::max());
		auto localProxyTransport = mUseTls ? "sips:127.0.0.1:" + to_string(localProxyPort) + ";tls-verify-outgoing=0"
		                                   : "sip:127.0.0.1:" + to_string(localProxyPort) + ";transport=tcp";
		cfg.getRoot()->get<GenericStruct>("global")->get<ConfigValue>("transports")->set(localProxyTransport);

		auto interDomainCfg = cfg.getRoot()->get<GenericStruct>("inter-domain-connections");
		interDomainCfg->get<ConfigValue>("keepalive-interval")->set(to_string(mKeepAliveInterval.count()));
		interDomainCfg->get<ConfigValue>("ping-pong-timeout-delay")->set(to_string(mPingPongTimoutDelay.count()));
		interDomainCfg->get<ConfigValue>("reconnection-delay")->set("0");
	}
	void testExec() override {
		sofiasip::Url proxyUri{"sip:127.0.0.1:" + to_string(mRemoteProxyPort) +
		                       ";transport=" + (mUseTls ? "tls" : "tcp")};
		auto drm = mAgent->getDRM();
		auto reg = make_shared<DomainRegistration>(*drm, "local.sip.example.org", proxyUri, "",
		                                           sofiasip::TlsConfigInfo{}, "", 0);
		drm->addDomainRegistration(reg);

		SLOGD << "Starting domain registration";
		reg->start();
		BC_HARD_ASSERT_TRUE(waitFor([&drm]() { return drm->getRegistrationCount() == 1; }, 1s));

		SLOGD << "Waiting for several PING sendings";
		// Check that the connection hasn't been broken for the last seconds
		const auto timeout = (2 * mKeepAliveInterval) * 1.05;
		BC_HARD_ASSERT_FALSE(waitFor([&reg]() { return reg->getRegistrationStatus()->read() != 200; }, timeout));

		SLOGD << "Pausing the remote proxy in order to simulate a network problem";
		mRemoteProxy.pause();
		const auto timeout2 = (mKeepAliveInterval + mPingPongTimoutDelay) * 1.05;
		BC_HARD_ASSERT_TRUE(waitFor([&reg]() { return reg->getRegistrationStatus()->read() == 503; }, timeout2));

		SLOGD << "Resume the remote proxy and wait for a new successfull registration";
		mRemoteProxy.unpause();
		BC_HARD_ASSERT_TRUE(waitFor([&reg]() { return reg->getRegistrationStatus()->read() == 200; }, 1s));

		SLOGD << "Stopping domain registration";
		reg->stop();
		BC_HARD_ASSERT_TRUE(waitFor([&drm]() { return drm->getRegistrationCount() == 0; }, 1s));
	}

	// Private attributes
	ProxyServerProcess mRemoteProxy{};
	int mRemoteProxyPort{0};
	std::string mRemoteProxyTransport{};
	bool mUseTls{false};
	std::chrono::seconds mKeepAliveInterval{2};
	std::chrono::seconds mPingPongTimoutDelay{1};
};

template <typename ProtoT>
class RFC5626ReconnectOnPongTimeout : public RFC5626ReconnectOnPongTimeoutBase {
public:
	RFC5626ReconnectOnPongTimeout() : RFC5626ReconnectOnPongTimeoutBase{ProtoT::isTls} {
	}
};

struct TCP {
	static constexpr auto isTls = false;
};

struct TLS {
	static constexpr auto isTls = true;
};

namespace {
TestSuite _("Domain registration",
            {
                TEST_NO_TAG("Ping-Pong: reconnect on PONG timeout (TCP)", run<RFC5626ReconnectOnPongTimeout<TCP>>),
                TEST_NO_TAG("Ping-Pong: reconnect on PONG timeout (TLS)", run<RFC5626ReconnectOnPongTimeout<TLS>>),
            });
}
} // namespace tester
} // namespace flexisip
