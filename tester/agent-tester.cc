/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <memory>
#include <utility>
#include <vector>

#include "bctoolbox/ownership.hh"
#include <bctoolbox/tester.h>

#include <sofia-sip/msg_buffer.h>
#include <sofia-sip/msg_header.h>
#include <sofia-sip/sip_protos.h>

#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "tester.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/transport/tls-connection.hh"

using namespace std;

namespace flexisip::tester {

class TransportsAndIsUsTest : public AgentTest {
private:
	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("sips:localhost:6060;maddr=127.0.0.2 sips:localhost:6062");
		globalCfg->get<ConfigStringList>("aliases")->set("localhost aRandomAlias 8.8.8.8");

		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigBoolean>("enabled")->set("true");
	}

	void testExec() override {
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
 * Config based classes are used to customize RFC5626KeepAliveWithCRLF test.
 */
class TransportConfig {
public:
	virtual ~TransportConfig() = default;

	const string& getHost() const noexcept {
		return mHost;
	}
	const string& getPort() const noexcept {
		return mPort;
	}
	const string& getProtoName() const noexcept {
		return mProtoName;
	}
	auto useOutbound() const noexcept {
		return mUseOutbound;
	}

	/**
	 * Create and configure the TlsConnection object.
	 */
	virtual unique_ptr<TlsConnection> makeConnection() = 0;
	/**
	 * Configure the agent. It is usually used to populate the 'transport=' line.
	 */
	virtual void configureAgent(GenericManager& cfg) {
		auto registrarCfg = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarCfg->get<ConfigValue>("enabled")->set("true");
		registrarCfg->get<ConfigValue>("reg-domains")->set("sip.example.org");
	}

protected:
	template <typename T>
	TransportConfig(T&& protoName) : mProtoName{forward<T>(protoName)} {
	}

	string mHost{"localhost"}; /**< Listening address of the Agent */
	string mPort{"6060"};      /**< Listening port of the Agent */
	string mProtoName;         /**< String that describe the protocol used for the test ('TCP' or 'TLS'). */
	bool mUseOutbound{true};   /**< Place 'Supported: outbound' header in the REGISTER request. */
};

/**
 * Config to test TCP transport.
 */
class TcpConfig : public TransportConfig {
public:
	TcpConfig() : TransportConfig("TCP") {
	}

	unique_ptr<TlsConnection> makeConnection() override {
		return make_unique<TlsConnection>(mHost, mPort, "", "");
	}
	void configureAgent(GenericManager& cfg) override {
		TransportConfig::configureAgent(cfg);
		ostringstream transport{};
		transport << "sip:" << mHost << ":" << mPort << ";transport=tcp";
		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set(transport.str());
	}
};

/**
 * Base class for Config object that allows to test TLS transports.
 */
class TlsConfig : public TransportConfig {
public:
	unique_ptr<TlsConnection> makeConnection() override {
		return make_unique<TlsConnection>(mHost, mPort);
	}
	void configureAgent(GenericManager& cfg) override {
		TransportConfig::configureAgent(cfg);
		ostringstream transport{};
		transport << "sips:" << mHost << ":" << mPort;

		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set(transport.str());
	}

protected:
	TlsConfig() : TransportConfig("TLS") {
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

		auto certfile = static_cast<string>(bc_tester_get_resource_dir_prefix()) + "/cert/self.signed.cert.test.pem";
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
class InternalTransportConfig : public TransportConfig {
public:
	InternalTransportConfig() : TransportConfig("TCP") {
	}

	unique_ptr<TlsConnection> makeConnection() override {
		return make_unique<TlsConnection>(mHost, mPort, "", "");
	}
	void configureAgent(GenericManager& cfg) override {
		TransportConfig::configureAgent(cfg);
		ostringstream transport{};
		transport << "sip:" << mHost << ":" << mPort << ";transport=tcp";
		auto* globalCfg = cfg.getRoot()->get<GenericStruct>("global");
		globalCfg->get<ConfigStringList>("transports")->set("");

		auto* clusterCfg = cfg.getRoot()->get<GenericStruct>("cluster");
		clusterCfg->get<ConfigValue>("enabled")->set("true");
		clusterCfg->get<ConfigValue>("internal-transport")->set(transport.str());
	}
};

/**
 * Config to test that no PONG is sent by the proxy if the client hasn't declared to
 * support 'outbound' feature.
 */
class OutboundNotSupported : public TcpConfig {
public:
	OutboundNotSupported() {
		mUseOutbound = false;
	}
};

class TransportTest : public AgentTest {
protected:
	unique_ptr<TransportConfig> mConfig;

	TransportTest(unique_ptr<TransportConfig>&& config) : mConfig(move(config)) {
	}

	unique_ptr<TlsConnection> connect() {
		auto conn = mConfig->makeConnection();
		SLOGD << "Connecting on " << mConfig->getHost() << ":" << mConfig->getPort() << " using "
		      << mConfig->getProtoName();
		conn->connectAsync(*mRoot->getCPtr(), []() {});
		BC_HARD_ASSERT_TRUE(waitFor([&conn]() { return conn->isConnected(); }, 1s));
		return conn;
	}

	sofiasip::MsgSip sendRegister(TlsConnection& conn, const char* cseq, const string instanceId = "") {
		const auto localPort = conn.getLocalPort();
		const auto& protoName = mConfig->getProtoName();
		const auto transport = StringUtils::toLower(protoName);
		const auto supportedHeader = mConfig->useOutbound() ? "Supported: outbound\r\n" : "";

		ostringstream reqStream{};
		reqStream << "REGISTER sip:localhost:" << mConfig->getPort() << ";transport=" << transport << " SIP/2.0\r\n"
		          << "Via: SIP/2.0/" << protoName << " localhost:" << localPort
		          << ";rport;branch=z9hG4bKg75aK9eUg15NS\r\n"
		          << "Max-Forwards: 70\r\n"
		          << "From: sip:user@sip.example.org;tag=5Nm3000eSje9a\r\n"
		          << "To: sip:user@sip.example.org\r\n"
		          << "Call-ID: 50573f6b-7d6d-123b-5b92-04d4c4159ac6\r\n"
		          << "CSeq: " << cseq << " REGISTER\r\n"
		          << "Contact: <sip:user@localhost:" << localPort << ">;transport=" << transport << instanceId << "\r\n"
		          << "Expires: 600\r\n"
		          << supportedHeader << "Content-Length: 0\r\n"
		          << "\r\n";
		const auto req = reqStream.str();

		SLOGD << "Sending request:\n" << req;
		const auto nwritten = conn.write(req);
		BC_ASSERT_EQUAL(nwritten, req.size(), int, "%i");
		BC_HARD_ASSERT_TRUE(nwritten == static_cast<int>(req.size()));

		sofiasip::MsgSip msg(ownership::owned(msg_create(sip_default_mclass(), 0)));
		constexpr auto bufSize = 1024;
		auto buf = msg_buf_alloc(msg.getMsg(), bufSize);
		const auto responseReceived = waitFor(
		    [&msg, &buf, &conn]() {
			    const auto nread = conn.read(buf, bufSize);
			    BC_HARD_ASSERT_TRUE(nread >= 0);
			    if (nread > 0) {
				    msg_buf_commit(msg.getMsg(), nread, 1);
				    return true;
			    }
			    return false;
		    },
		    1s);
		BC_HARD_ASSERT_TRUE(responseReceived);
		BC_HARD_ASSERT_TRUE(msg_extract(msg.getMsg()) > 0);

		return msg;
	}

private:
	// Private methods
	void onAgentConfiguration(GenericManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		mConfig->configureAgent(cfg);
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
class RFC5626KeepAliveWithCRLFBase : public TransportTest {
protected:
	RFC5626KeepAliveWithCRLFBase(unique_ptr<TransportConfig>&& config) : TransportTest(move(config)) {
	}

private:
	// Private methods
	void testExec() override {
		auto conn = connect();

		SLOGD << "Send register to the agent and wait for successful response";
		doRegistration(*conn);

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
		if (mConfig->useOutbound()) {
			BC_HARD_ASSERT_TRUE(waitFor(pongReceived, 1s));
		} else {
			BC_HARD_ASSERT_FALSE(waitFor(pongReceived, 1s));
		}
	}

	void doRegistration(TlsConnection& conn) {
		const auto msg =
		    sendRegister(conn, "966679804", ";+sip.instance=\"<urn:uuid:61643831-6465-4037-a135-356537616633>\"");

		const auto sip = msg.getSip();
		BC_HARD_ASSERT_TRUE(sip->sip_status != nullptr);
		BC_ASSERT_EQUAL(sip->sip_status->st_status, 200, int, "%i");
		BC_HARD_ASSERT_TRUE(sip->sip_status->st_status == 200);
		BC_HARD_ASSERT_TRUE(sip->sip_cseq->cs_method == sip_method_register);
	}
};

class CSeqIsCheckedOnRegisterWithoutInstanceId : public TransportTest {
public:
	CSeqIsCheckedOnRegisterWithoutInstanceId() : TransportTest(make_unique<TcpConfig>()) {
	}

private:
	void testExec() override {
		auto conn = connect();
		{ // REGISTERing without Instance-ID will follow the rules of the RFC 3261
			const auto msg = sendRegister(*conn, "2");

			const auto sip = msg.getSip();
			BC_HARD_ASSERT_TRUE(sip->sip_status != nullptr);
			BC_ASSERT_EQUAL(sip->sip_status->st_status, 200, int, "%i");
			BC_HARD_ASSERT_TRUE(sip->sip_status->st_status == 200);
			BC_HARD_ASSERT_TRUE(sip->sip_cseq->cs_method == sip_method_register);
		}
		{ // Sending a REGISTER with the same Call-ID but a lesser CSeq is invalid (<)
			const auto msg = sendRegister(*conn, "1");

			const auto sip = msg.getSip();
			BC_HARD_ASSERT_TRUE(sip->sip_status != nullptr);
			BC_ASSERT_EQUAL(sip->sip_status->st_status, 400, int, "%i");
			BC_HARD_ASSERT_TRUE(sip->sip_cseq->cs_method == sip_method_register);
		}
		{ // ...Or with the same CSeq (==)
			const auto msg = sendRegister(*conn, "2");

			const auto sip = msg.getSip();
			BC_HARD_ASSERT_TRUE(sip->sip_status != nullptr);
			BC_ASSERT_EQUAL(sip->sip_status->st_status, 400, int, "%i");
			BC_HARD_ASSERT_TRUE(sip->sip_cseq->cs_method == sip_method_register);
		}
	}
};

/**
 * Helper template class to easily instantiate RFC5626KeepAliveWithCRLFBase with
 * the given Config instance.
 */
template <typename ConfigT>
class RFC5626KeepAliveWithCRLF : public RFC5626KeepAliveWithCRLFBase {
public:
	RFC5626KeepAliveWithCRLF() : RFC5626KeepAliveWithCRLFBase{make_unique<ConfigT>()} {
	}
};

class ReplyToOptionRequestTest : public AgentTest {
private:
	// Private methods
	void onAgentConfiguration(GenericManager& cfg) override {
		const auto* globalSection = cfg.getRoot()->get<GenericStruct>("global");
		globalSection->get<ConfigValue>("transports")->set(kProxyURI);
		globalSection->get<ConfigValue>("aliases")->set("localhost "s + kDomain);
	}

	void testExec() override {
		using namespace sofiasip;

		const auto fromURI = "sip:alice@"s + kDomain;
		const auto toURI = "sip:"s + kDomain;
		const auto& requestURI = toURI;

		// Creating the SIP message
		auto optionRequest = make_unique<MsgSip>();
		optionRequest->makeAndInsert<SipHeaderRequest>(sip_method_options, requestURI);
		optionRequest->makeAndInsert<SipHeaderFrom>(fromURI, "dummyTag");
		optionRequest->makeAndInsert<SipHeaderTo>(toURI);
		optionRequest->makeAndInsert<SipHeaderCallID>(kDomain);
		optionRequest->makeAndInsert<SipHeaderCSeq>(20u, sip_method_options);

		// Instantiate the client and send the request through an outgoing transaction
		auto client = NtaAgent{mRoot, "sip:localhost:0"};
		auto transaction = client.createOutgoingTransaction(move(optionRequest), kProxyURI);

		// Wait for the transaction completion and check that the server has replied 200.
		BC_ASSERT_TRUE(waitFor([transaction]() { return transaction->isCompleted(); }, 1s));
		BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 200);
	}

	// Private attributes
	static constexpr auto kDomain = "sip.example.org";
	static constexpr auto kProxyPort = "6060";
	static const std::string kProxyURI;
};

const std::string ReplyToOptionRequestTest::kProxyURI =
    "sip:"s + kDomain + ":" + kProxyPort + ";maddr=127.0.0.1;transport=tcp";

namespace {
using TCP = TcpConfig;
using NewTLS = NewTlsConfig;
using LegacyTLS = LegacyTlsConfig;
using InternalTransport = InternalTransportConfig;

TestSuite _{"Agent unit tests",
            {
                CLASSY_TEST(CSeqIsCheckedOnRegisterWithoutInstanceId),
                TEST_NO_TAG("Transports loading from conf and isUs method testing", run<TransportsAndIsUsTest>),
                TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on TCP", run<RFC5626KeepAliveWithCRLF<TCP>>),
                TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on TLS", run<RFC5626KeepAliveWithCRLF<NewTLS>>),
                TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on TLS (legacy parameters)",
                            run<RFC5626KeepAliveWithCRLF<LegacyTLS>>),
                TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) on the internal transport",
                            run<RFC5626KeepAliveWithCRLF<InternalTransport>>),
                TEST_NO_TAG("Keep-Alive with CRLF (RFC5626) - no PONG if 'outbound' not supported",
                            run<RFC5626KeepAliveWithCRLF<OutboundNotSupported>>),
                TEST_NO_TAG("Agent replies to OPTION requests", run<ReplyToOptionRequestTest>),
            }};
} // namespace

} // namespace flexisip::tester
