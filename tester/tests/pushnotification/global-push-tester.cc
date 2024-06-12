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

#include "tester.hh"

#include "module-pushnotification.hh"
#include "pushnotification/generic/generic-http-client.hh"
#include "utils/asserts.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/http-mock/http-mock.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
using namespace pushnotification;
namespace tester {
using namespace http_mock;

// ####################################################################################################################
// ################################################### ABSTRACT TEST CLASS ############################################
// ####################################################################################################################

class GlobalPushTest : public AgentTest {
public:
	GlobalPushTest() : mHttpMock{{"/"}, &mRequestReceivedCount}, mMockPort{mHttpMock.serveAsync()} {
		BC_HARD_ASSERT_TRUE(mMockPort > -1);
	}

	void testExec() override {

		executeScenario();

		BcAssert asserter{[this] { mRoot->step(1ms); }};
		BC_HARD_ASSERT_TRUE(asserter.iterateUpTo(10, [this] { return mRequestReceivedCount == 1; }));

		mHttpMock.forceCloseServer();
		mRoot->step(10ms); // needed to acknowledge mock server closing

		BC_HARD_ASSERT_CPP_EQUAL(mRequestReceivedCount, 1);
		const auto actualRequest = mHttpMock.popRequestReceived();
		BC_HARD_ASSERT_NOT_NULL(actualRequest);

		customAssert(actualRequest);
	}

	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		cfg.getRoot()
		    ->get<GenericStruct>("global")
		    ->get<ConfigValue>("transports")
		    ->set("sip:127.0.0.1:5660;transport=tcp");
		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigValue>("enabled")->set("false");
		cfg.getRoot()->get<GenericStruct>("module::MediaRelay")->get<ConfigValue>("enabled")->set("false");
		cfg.getRoot()->get<GenericStruct>("module::Router")->get<ConfigValue>("fork-late")->set("true");

		auto regCfg = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		regCfg->get<ConfigValue>("enabled")->set("true");
		regCfg->get<ConfigValue>("reg-domains")->set("sip.example.org");

		auto pushCfg = cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("enabled")->set("true");
		pushCfg->get<ConfigValue>("apple")->set("false");
		pushCfg->get<ConfigValue>("firebase")->set("false");

		customizeConf(cfg);
	}

protected:
	virtual void executeScenario() = 0;
	virtual void customAssert(const shared_ptr<Request>& actualRequest) = 0;
	virtual void customizeConf(ConfigManager& cfg) = 0;

public:
	int getMockPort() const {
		return mMockPort;
	}

private:
	std::atomic_int mRequestReceivedCount = 0;
	HttpMock mHttpMock;
	int mMockPort;
};

// ####################################################################################################################
// ################################################### ACTUAL TESTS ###################################################
// ####################################################################################################################

/**
 * Configure module::PushNotification to use the Generic pusher, using http2 and POST.
 * Send a message between 2 participants.
 * Assert that a push is correctly sent.
 */
class GenericHttp2PushMessage : public GlobalPushTest {
protected:
	void executeScenario() override {
		auto sender = ClientBuilder(*mAgent).build("creme@sip.example.org");
		auto receiver = ClientBuilder(*mAgent).setApplePushConfig().build("popo@sip.example.org");

		auto chatroom = sender.chatroomBuilder().setSubject("TestPush").build({receiver.getMe()});
		chatroom->createMessageFromUtf8("...")->send();
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->body, "...");
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "POST");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/genericMessage");
		BC_ASSERT_CPP_EQUAL(actualRequest->headers.size(), 2);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.count("content-type"), 1);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.find("content-type")->second.value, "text/plain");
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.count("content-length"), 1);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.find("content-length")->second.value, "3");
	}

	void customizeConf(ConfigManager& cfg) override {
		auto pushCfg = cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("external-push-uri")
		    ->set("https://127.0.0.1:" + to_string(getMockPort()) + "/genericMessage");
		pushCfg->get<ConfigValue>("external-push-method")->set("POST");
		pushCfg->get<ConfigValue>("external-push-protocol")->set("http2");
	}
};

/**
 * Configure module::PushNotification to use the Generic pusher, using http2 and GET.
 * Start a call between 2 participants.
 * Assert that a push is correctly sent.
 */
class GenericHttp2PushCall : public GlobalPushTest {
protected:
	void executeScenario() override {
		auto sender = ClientBuilder(*mAgent).build("creme@sip.example.org");
		auto receiver = ClientBuilder(*mAgent).setApplePushConfig().build("popo@sip.example.org");

		auto call = sender.call(receiver);
		call->terminate();
	}

	void customAssert(const shared_ptr<Request>& actualRequest) override {
		BC_ASSERT_CPP_EQUAL(actualRequest->body, "");
		BC_ASSERT_CPP_EQUAL(actualRequest->method, "GET");
		BC_ASSERT_CPP_EQUAL(actualRequest->path, "/genericCall");
		BC_ASSERT_CPP_EQUAL(actualRequest->headers.size(), 2);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.count("content-type"), 1);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.find("content-type")->second.value, "text/plain");
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.count("content-length"), 1);
		BC_HARD_ASSERT_CPP_EQUAL(actualRequest->headers.find("content-length")->second.value, "0");
	}

	void customizeConf(ConfigManager& cfg) override {
		auto pushCfg = cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("external-push-uri")
		    ->set("https://127.0.0.1:" + to_string(getMockPort()) + "/genericCall");
		pushCfg->get<ConfigValue>("external-push-method")->set("GET");
		pushCfg->get<ConfigValue>("external-push-protocol")->set("http2");
	}
};

/**
 * Minimal test (as we don't have HTTP/1 mock right now)
 * Configure module::PushNotification to use the Generic pusher, using http.
 * Assert that a GenericHttpClient is instantiated.
 */
class GenericHttpPushMessageMinimal : public AgentTest {
protected:
	void testExec() override {
		const auto& modulePush = dynamic_pointer_cast<PushNotification>(mAgent->findModule("PushNotification"));
		BC_HARD_ASSERT_NOT_NULL(modulePush);
		const auto& pushClients = modulePush->getService()->getClients();
		BC_HARD_ASSERT_CPP_EQUAL(pushClients.size(), 1);
		BC_HARD_ASSERT_NOT_NULL(dynamic_pointer_cast<GenericHttpClient>(pushClients.begin()->second));
	}

	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);
		cfg.getRoot()
		    ->get<GenericStruct>("global")
		    ->get<ConfigValue>("transports")
		    ->set("sip:127.0.0.1:5960;transport=tcp");
		cfg.getRoot()->get<GenericStruct>("module::DoSProtection")->get<ConfigValue>("enabled")->set("false");
		cfg.getRoot()->get<GenericStruct>("module::MediaRelay")->get<ConfigValue>("enabled")->set("false");
		cfg.getRoot()->get<GenericStruct>("module::Router")->get<ConfigValue>("fork-late")->set("true");

		auto regCfg = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		regCfg->get<ConfigValue>("enabled")->set("true");
		regCfg->get<ConfigValue>("reg-domains")->set("sip.example.org");

		auto pushCfg = cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("enabled")->set("true");
		pushCfg->get<ConfigValue>("apple")->set("false");
		pushCfg->get<ConfigValue>("firebase")->set("false");

		// Test specific
		cfg.getRoot()->get<GenericStruct>("module::PushNotification");
		pushCfg->get<ConfigValue>("external-push-uri")->set("https://127.0.0.1:3000/genericMessage");
		pushCfg->get<ConfigValue>("external-push-method")->set("POST");
		pushCfg->get<ConfigValue>("external-push-protocol")->set("http");
	}
};

namespace {
TestSuite _("Push notification global tests",
            {
                CLASSY_TEST(GenericHttp2PushMessage),
                CLASSY_TEST(GenericHttp2PushCall),
                CLASSY_TEST(GenericHttpPushMessageMinimal),
            });
} // namespace

} // namespace tester
} // namespace flexisip
