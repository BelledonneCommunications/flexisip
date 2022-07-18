/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <boost/asio.hpp>

#include <bctoolbox/tester.h>

#include "tester.hh"
#include "utils/test-paterns/agent-test.hh"
#include "utils/transport/tls-connection.hh"

using namespace std;

namespace flexisip {
namespace tester {

class TransportsAndIsUsTest : public AgentTest {
private:
	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("sips:localhost:6060;maddr=127.0.0.2 sips:localhost:6062");
		globalCfg->get<ConfigStringList>("aliases")->set("localhost aRandomAlias 8.8.8.8");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("true");
	}

	void onExec() override {
		// 6060
		BC_ASSERT_TRUE(mAgent->isUs("localhost", "6060", false)); // hostname
		BC_ASSERT_TRUE(mAgent->isUs("127.0.0.1", "6060", false)); // resolved ipv4
		BC_ASSERT_TRUE(mAgent->isUs("::1", "6060", false));       // resolved ipv6
		BC_ASSERT_TRUE(mAgent->isUs("[::1]", "6060", false));     // resolved ipv6
		BC_ASSERT_TRUE(mAgent->isUs("127.0.0.2", "6060", false)); // maddr biding

		// 6062
		BC_ASSERT_TRUE(mAgent->isUs("localhost", "6062", false)); // hostname
		BC_ASSERT_TRUE(mAgent->isUs("127.0.0.1", "6062", false)); // resolved ipv4 or auto biding
		BC_ASSERT_TRUE(mAgent->isUs("::1", "6062", false));       // resolved ipv6 or auto biding
		BC_ASSERT_TRUE(mAgent->isUs("[::1]", "6062", false));     // resolved ipv6 or auto biding

		// With aliases
		BC_ASSERT_TRUE(mAgent->isUs("localhost", "evenWithABadPort", true));
		BC_ASSERT_TRUE(mAgent->isUs("aRandomAlias", "evenWithABadPort", true));
		BC_ASSERT_TRUE(mAgent->isUs("8.8.8.8", "evenWithABadPort", true));

		// No match without aliases
		BC_ASSERT_FALSE(mAgent->isUs("localhost", "badPort", false));
		BC_ASSERT_FALSE(mAgent->isUs("badHost", "6060", false));

		// No match with aliases
		BC_ASSERT_FALSE(mAgent->isUs("anotherRandomAlias", "6060", true));
	}
};

/**
 * Check that the Agent answers to CRLF-based ping request.
 * 1. Instantiate an agent listening on localhost
 * 2. Make a simple client TCP/TLS connection by using TlsConnection object.
 * 3. Send a double CRLF sequence and wait for a single CRLF sequence as response.
 *
 * This is a generic test which need to be customized by given a Config object
 * on construction. Available Config class are declared as subclasses.
 */
class RFC5626KeepAliveWithCRLFBase : public AgentTest {
public:
	/**
	 * Config based classes are used to customize RFC5626KeepAliveWithCRLF test.
	 */
	class Config {
	public:
		virtual ~Config() = default;

		const std::string& getHost() const noexcept {
			return mHost;
		}
		const std::string& getPort() const noexcept {
			return mHost;
		}
		const std::string& getProtoName() const noexcept {
			return mProtoName;
		}

		/**
		 * Create and configure the TlsConnection object.
		 */
		virtual std::unique_ptr<TlsConnection> makeConnection() = 0;
		/**
		 * Configure the agent. It is usually used to populate the 'transport=' line.
		 */
		virtual void configureAgent(GenericManager& cfg) = 0;

	protected:
		template <typename T>
		Config(T&& protoName) : mProtoName{std::forward<T>(protoName)} {
		}

		std::string mHost{"localhost"}; /**< Listening address of the Agent */
		std::string mPort{"6060"};      /**< Listening port of the Agent */
		std::string mProtoName;         /**< String that describe the protocol used for the test ('TCP' or 'TLS'). */
	};

	/**
	 * Config to test TCP transport.
	 */
	class TcpConfig : public Config {
	public:
		TcpConfig() : Config("TCP") {
		}

		std::unique_ptr<TlsConnection> makeConnection() override {
			return make_unique<TlsConnection>(mHost, mPort, "", "");
		}
		void configureAgent(GenericManager& cfg) override {
			ostringstream transport{};
			transport << "sip:" << mHost << ":" << mPort << ";transport=tcp";
			auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
			globalCfg->get<ConfigStringList>("transports")->set(transport.str());
		}
	};

	/**
	 * Base class for Config object that allows to test TLS transports.
	 */
	class TlsConfig : public Config {
	public:
		std::unique_ptr<TlsConnection> makeConnection() override {
			return make_unique<TlsConnection>(mHost, mPort);
		}
		void configureAgent(GenericManager& cfg) override {
			ostringstream transport{};
			transport << "sips:" << mHost << ":" << mPort;

			auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
			globalCfg->get<ConfigStringList>("transports")->set(transport.str());
		}

	protected:
		TlsConfig() : Config("TLS") {
		}
	};

	/**
	 * Config to test TLS transport by using the new parameters to set the certificate and the private key.
	 */
	class NewTlsConfig : public TlsConfig {
	public:
		using TlsConfig::TlsConfig;

		void configureAgent(GenericManager& cfg) override {
			TlsConfig::configureAgent(cfg);

			auto certfile =
			    static_cast<string>(bc_tester_get_resource_dir_prefix()) + "/cert/self.signed.cert.test.pem";
			auto keyfile = static_cast<string>(bc_tester_get_resource_dir_prefix()) + "/cert/self.signed.key.test.pem";

			auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
			globalCfg->get<ConfigString>("tls-certificates-file")->set(certfile);
			globalCfg->get<ConfigString>("tls-certificates-private-key")->set(keyfile);
		}
	};

	/**
	 * Same as #NewTlsConfig but use the legacy parameters.
	 */
	class LegacyTlsConfig : public TlsConfig {
	public:
		using TlsConfig::TlsConfig;

		void configureAgent(GenericManager& cfg) override {
			TlsConfig::configureAgent(cfg);

			auto certDir = static_cast<string>(bc_tester_get_resource_dir_prefix()) + "/cert/self.signed.legacy";
			auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
			globalCfg->get<ConfigString>("tls-certificates-dir")->set(certDir);
		}
	};

	/**
	 * Config to test the transport specified with 'cluster/internal-transport' parameter.
	 */
	class InternalTransportConfig : public Config {
	public:
		InternalTransportConfig() : Config("TCP") {
		}

		std::unique_ptr<TlsConnection> makeConnection() override {
			return make_unique<TlsConnection>(mHost, mPort, "", "");
		}
		void configureAgent(GenericManager& cfg) override {
			ostringstream transport{};
			transport << "sip:" << mHost << ":" << mPort << ";transport=tcp";
			auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
			globalCfg->get<ConfigStringList>("transports")->set("");

			auto* clusterCfg = cfg.getRoot()->get<GenericStruct>("cluster");
			clusterCfg->get<ConfigValue>("enabled")->set("true");
			clusterCfg->get<ConfigValue>("internal-transport")->set(transport.str());
		}
	};

protected:
	RFC5626KeepAliveWithCRLFBase(const std::shared_ptr<Config>& config) : mConfig{config} {
	}

private:
	// Private methods
	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		mConfig->configureAgent(cfg);
	}

	void onExec() override {
		auto conn = mConfig->makeConnection();

		SLOGD << "Connecting on " << mConfig->getHost() << ":" << mConfig->getPort() << " using "
		      << mConfig->getProtoName();
		auto connected = false;
		conn->connectAsync(*mRoot->getCPtr(), [&conn, &connected]() { connected = conn->isConnected(); });
		BC_HARD_ASSERT_TRUE(waitFor([&connected]() { return connected; }, 1s));

		SLOGD << "Sending double CRLF";
		BC_HARD_ASSERT_TRUE(conn->write("\r\n\r\n") > 0);

		SLOGD << "Waiting for reception of a single CRLF";
		auto pongReceived = [&conn]() {
			vector<char> readData{};
			conn->read(readData, 2);
			if (readData.size() > 0) {
				string readDataStr{readData.cbegin(), readData.cend()};
				if (readDataStr == "\r\n") return true;
			}
			return false;
		};
		BC_HARD_ASSERT_TRUE(waitFor(pongReceived, 1s));
	}

	// Private attributes
	std::shared_ptr<Config> mConfig;
};

/**
 * Helper template class to easily instantiate RFC5626KeepAliveWithCRLFBase with
 * the given Config instance.
 */
template <typename ConfigT>
class RFC5626KeepAliveWithCRLF : public RFC5626KeepAliveWithCRLFBase {
public:
	RFC5626KeepAliveWithCRLF() : RFC5626KeepAliveWithCRLFBase{make_shared<ConfigT>()} {
	}
};

using TCP = RFC5626KeepAliveWithCRLFBase::TcpConfig;
using NewTLS = RFC5626KeepAliveWithCRLFBase::NewTlsConfig;
using LegacyTLS = RFC5626KeepAliveWithCRLFBase::LegacyTlsConfig;
using InternalTransport = RFC5626KeepAliveWithCRLFBase::InternalTransportConfig;

static test_t tests[] = {
    TEST_NO_TAG("Transports loading from conf and isUs method testing", run<TransportsAndIsUsTest>),
    TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on TCP", run<RFC5626KeepAliveWithCRLF<TCP>>),
    TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on TLS", run<RFC5626KeepAliveWithCRLF<NewTLS>>),
    TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on TLS (legacy parameters)", run<RFC5626KeepAliveWithCRLF<LegacyTLS>>),
    TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on the internal transport",
                run<RFC5626KeepAliveWithCRLF<InternalTransport>>)};

test_suite_t agentSuite = {
    "Agent unit tests", nullptr, nullptr, nullptr, nullptr, sizeof(tests) / sizeof(tests[0]), tests};

} // namespace tester
} // namespace flexisip
