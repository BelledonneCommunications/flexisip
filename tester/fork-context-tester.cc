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

#include <chrono>

#include "flexisip/module-router.hh"
#include "flexisip/registrar/registar-listeners.hh"

#include "agent.hh"
#include "fork-context/fork-context-base.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/registrar-db.hh"
#include "tester.hh"
#include "utils/bellesip-utils.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-core.hh"
#include "utils/contact-inserter.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip::tester {
namespace {

bool responseReceived = false;

void nullMaxForwardAndForkBasicContext() {
	// Agent initialization.
	const auto& suRoot = make_shared<sofiasip::SuRoot>();
	const auto& config = make_shared<ConfigManager>();
	config->load(bcTesterRes("config/flexisip_fork_context.conf"));
	const auto* globalConf = config->getRoot()->get<GenericStruct>("global");
	globalConf->get<ConfigStringList>("transports")->set("sip:127.0.0.1:5360");
	const auto* registrarConf = config->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	// Inserting a new contact into the registrarDB.
	const auto& registrarDb = make_shared<RegistrarDb>(suRoot, config);
	ContactInserter inserter{*registrarDb};
	inserter.withGruu(true).setExpire(1000s).setAor("sip:participant1@127.0.0.1").insert();

	const auto agent = make_shared<Agent>(suRoot, config, make_shared<AuthDb>(config), registrarDb);
	agent->start("", "");

	// Sending a request with Max-Forwards = 0.
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "UDP",
	    [](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 483);
			    responseReceived = true;
		    }
	    },
	    nullptr,
	};

	belleSipUtils.sendRawRequest("OPTIONS sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                             "Via: SIP/2.0/UDP 10.10.10.10:5060;rport;branch=z9hG4bK1439638806\r\n"
	                             "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                             "To: <sip:participant1@127.0.0.1>\r\n"
	                             "Call-ID: 1053183492\r\n"
	                             "CSeq: 1 OPTIONS\r\n"
	                             "Contact: <sip:jehan-mac@192.168.1.8:5062>\r\n"
	                             "Max-Forwards: 0\r\n"
	                             "User-Agent: BelleSipUtils\r\n"
	                             "Content-Length: 0\r\n\r\n");

	// Loop on Agent and belleSipUtils, until a response is received by the belle-sip stack.
	// If after 5s (MUST be inferior to ForkBasicContext timeout) nothing is received, we break the loop and the test
	// should fail.
	CoreAssert{suRoot, belleSipUtils}.waitUntil(5s, []() { return LOOP_ASSERTION(responseReceived); }).assert_passed();

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(responseReceived);
	if (moduleRouter) {
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountForks->finish->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountBasicForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountBasicForks->finish->read(), 1);
	}
}

void notRtpPortAndForkCallContext() {
	// Agent initialization.
	const auto& suRoot = make_shared<sofiasip::SuRoot>();
	const auto& config = make_shared<ConfigManager>();
	config->load(bcTesterRes("config/flexisip_fork_context_media_relay.conf"));
	const auto* registrarConf = config->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	// Inserting a new contact into the registrarDB.
	const auto& registrarDb = make_shared<RegistrarDb>(suRoot, config);
	ContactInserter inserter{*registrarDb};
	inserter.withGruu(true).setExpire(1000s).setAor("sip:participant1@127.0.0.1").insert();

	const auto agent = make_shared<Agent>(suRoot, config, make_shared<AuthDb>(config), registrarDb);
	agent->start("", "");

	// Sending a request with Max-Forwards = 0.
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "UDP",
	    [](const int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 500);
			    responseReceived = true;
		    }
	    },
	    nullptr,
	};

	belleSipUtils.sendRawRequest(
	    // Sip message.
	    "INVITE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	    "Via: SIP/2.0/UDP 12.34.56.78:12345;branch=z9hG4bK-d8754z-4d7620d2feccbfac-1---d8754z-\r\n"
	    "To: <sip:participant1@127.0.0.1>\r\n"
	    "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	    "Contact: <sip:anthony@127.0.0.1>\r\n"
	    "Call-ID: stub-call-id\r\n"
	    "CSeq: 20 INVITE\r\n"
	    "Max-Forwards: 70\r\n"
	    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
	    "Content-Type: application/sdp\r\n"
	    "User-Agent: BelleSipUtils\r\n\r\n",
	    // Request body.
	    "v=0\r\n"
	    "o=anthony.gauchy 3102 279 IN IP4 127.0.0.1\r\n"
	    "s=Talk\r\n"
	    "c=IN IP4 127.0.0.1\r\n"
	    "t=0 0\r\n"
	    "m=audio 7078 RTP/AVP 111 110 3 0 8 101\r\n"
	    "a=rtpmap:111 speex/16000\r\n"
	    "a=fmtp:111 vbr=on\r\n"
	    "a=rtpmap:110 speex/8000\r\n"
	    "a=fmtp:110 vbr=on\r\n"
	    "a=rtpmap:101 telephone-event/8000\r\n"
	    "a=fmtp:101 0-11\r\n"
	    "m=video 8078 RTP/AVP 99 97 98\r\n"
	    "c=IN IP4 192.168.0.18\r\n"
	    "b=AS:380\r\n"
	    "a=rtpmap:99 MP4V-ES/90000\r\n"
	    "a=fmtp:99 profile-level-id=3\r\n");

	// Loop on Agent and belleSipUtils, until a response is received by the belle-sip stack.
	// If after 5s (MUST be inferior to ForkBasicContext timeout) nothing is received, we break the loop and the test
	// should fail.
	CoreAssert{suRoot, belleSipUtils}.waitUntil(5s, []() { return LOOP_ASSERTION(responseReceived); }).assert_passed();

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(responseReceived);
	if (moduleRouter) {
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountForks->finish->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 1);
	}
}

/**
 * We send multiples message to a client with one idle device, to force the messages saving in DB.
 * Then we put the client back online and see if the messages are correctly delivered AND IN ORDER.
 * All along we check fork stats and client state.
 */
void globalOrderTestNoSql() {
	SLOGD << "Step 1: Setup";
	Server server{"/config/flexisip_fork_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto receiverClient = builder.build("sip:provencal_le_gaulois@sip.test.org");
	receiverClient.disconnect();

	auto isRequestAccepted = 0U;
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&isRequestAccepted](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 202);
			    isRequestAccepted++;
		    }
	    },
	    nullptr,
	};

	SLOGD << "Step 2: Send messages, non-urgent first";
	auto nbOfMessages = 20U;
	for (auto i = 1U; i <= nbOfMessages; ++i) {
		string rawBody{"C'est pas faux "s + to_string(i) + "\r\n\r\n"};
		stringstream rawRequest{};
		rawRequest << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
		           << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
		           << "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		           << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
		           << "CSeq: 20 MESSAGE\r\n"
		           << "Call-ID: Tvw6USHXYv" << i << "\r\n"
		           << "Max-Forwards: 70\r\n"
		           << "Route: <sip:127.0.0.1:5360;transport=tcp;lr>\r\n"
		           << "Supported: replaces, outbound, gruu\r\n"
		           << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
		           << "Content-Type: text/plain\r\n"
		           << "Content-Length: " << rawBody.size() << "\r\n\r\n";
		belleSipUtils.sendRawRequest(rawRequest.str(), rawBody);

		CoreAssert{server, belleSipUtils}
		    .wait([&isRequestAccepted, &i]() { return LOOP_ASSERTION(isRequestAccepted == i); })
		    .assert_passed();
	}

	SLOGD << "Step 3: Assert that fork is still present because device is offline. No db fork because no db.";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	CoreAssert asserter{server, receiverClient};
	asserter
	    .wait([&agent = server.getAgent(), &nbOfMessages] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    FAIL_IF(moduleRouter->mStats.mCountMessageForks->start->read() != nbOfMessages);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 0);

	SLOGD << "Step 4: Client REGISTER, then receive message";
	receiverClient.reconnect();
	asserter
	    .wait([&receiverClient, &nbOfMessages] {
		    FAIL_IF(receiverClient.getAccount()->getState() != linphone::RegistrationState::Ok);
		    FAIL_IF(static_cast<unsigned int>(receiverClient.getCore()->getUnreadChatMessageCount()) != nbOfMessages);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	SLOGD << "Step 5: Check messages order";
	auto messages = receiverClient.getChatMessages();
	auto order = 1U;
	for (const auto& message : messages) {
		auto actual = message->getUtf8Text();
		string expected{"C'est pas faux "s + to_string(order) + "\r\n\r\n"};
		BC_ASSERT_CPP_EQUAL(actual, expected);
		order++;
	}
	BC_ASSERT_CPP_EQUAL(order - 1, nbOfMessages);

	SLOGD << "Step 6: Check fork stats";
	asserter
	    .wait([&agent = server.getAgent(), &nbOfMessages] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    FAIL_IF(moduleRouter->mStats.mCountMessageForks->finish->read() != nbOfMessages);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), nbOfMessages);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), nbOfMessages);
}

/**
 * The main objective of this test is to ensure correct enforcement of the "message-delivery-timeout" configuration.
 * This means that after the specified duration of "message-delivery-timeout" seconds, the ForkMessageContext must be
 * destroyed, and the message should be forgotten, even if it was not delivered to all devices.
 *
 * To execute this test, the following steps are performed:
 *   1 - The test is initiated by sending a message from the caller to the callee, who has two clients: one online and
 * one offline.
 *   2  - Simultaneously, a call is initiated between the caller and the callee
 *   3 - Upon completion of the test and after the designated "message-delivery-timeout" period has elapsed, we verify
 * that the ForkMessageContext is destroyed while the ForkCallContext remains active.
 */
void messageDeliveryTimeoutTest() {
	Server server{"/config/flexisip_fork_context.conf"};
	server.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::Router")
	    ->get<ConfigValue>("message-delivery-timeout")
	    ->set("1");
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientVoip = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	calleeIdleClientVoip.disconnect();
	BC_ASSERT_PTR_NOT_NULL(callerClient.callWithEarlyCancel(calleeClient));

	const auto chatroom = callerClient.chatroomBuilder().build({calleeClient.getMe()});
	chatroom->createMessageFromUtf8("test")->send();

	CoreAssert asserter{server, callerClient, calleeClient, calleeIdleClientVoip};
	asserter
	    .wait([&agent = server.getAgent()] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    // The client may send an IMDN, so we cannot explicitly check that start value equals 1.
		    FAIL_IF(moduleRouter->mStats.mCountMessageForks->start->read() < 1);
		    // All ForkMessageContexts must be destroyed, since they should only live for one second.
		    FAIL_IF(moduleRouter->mStats.mCountMessageForks->finish->read() !=
		            moduleRouter->mStats.mCountMessageForks->start->read());

		    // ForkCallContext must still be present, waiting for delivery (one created, zero finished).
		    FAIL_IF(moduleRouter->mStats.mCountCallForks->start->read() != 1);
		    FAIL_IF(moduleRouter->mStats.mCountCallForks->finish->read() != 0);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

/**
 * The main objective of this test is to ensure correct enforcement of the "call-fork-timeout" configuration.
 * This means that after the specified duration of "call-fork-timeout" seconds, the ForkCallContext must be
 * destroyed, and the call should be forgotten, even if it was not delivered to all devices.
 *
 * To execute this test, the following steps are performed:
 *   1 - The test is initiated by sending a message from the caller to the callee, who has two clients: one online and
 * one offline.
 *   2  - Simultaneously, a call is initiated between the caller and the callee
 *   3 - Upon completion of the test and after the designated "call-fork-timeout" period has elapsed, we verify
 * that the ForkCallContext is destroyed while the ForkMessageContext remains active.
 */
void callForkTimeoutTest() {
	Server server{"/config/flexisip_fork_context.conf"};
	server.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::Router")
	    ->get<ConfigValue>("call-fork-timeout")
	    ->set("1");
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientVoip = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	calleeIdleClientVoip.disconnect();

	// Quick call without asserts, just to create a ForkCall.
	auto callParams = callerClient.getCore()->createCallParams(nullptr);
	auto addressWithoutGr = calleeClient.getAccount()->getContactAddress()->clone();
	addressWithoutGr->removeUriParam("gr");
	auto callerCall = callerClient.getCore()->inviteAddressWithParams(addressWithoutGr, callParams);
	callerCall->terminate();

	const auto chatroom = callerClient.chatroomBuilder().build({calleeClient.getMe()});
	chatroom->createMessageFromUtf8("test")->send();

	CoreAssert asserter{server, callerClient, calleeClient, calleeIdleClientVoip};
	asserter
	    .wait([&agent = server.getAgent()] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    // The client may send an IMDN, so we cannot explicitly check that start value equals 1.
		    FAIL_IF(moduleRouter->mStats.mCountMessageForks->start->read() < 1);
		    // At least 1 message must be still present.
		    FAIL_IF(moduleRouter->mStats.mCountMessageForks->finish->read() ==
		            moduleRouter->mStats.mCountMessageForks->start->read());

		    // ForkCallContext must be destroyed, since they should only live for one second.
		    FAIL_IF(moduleRouter->mStats.mCountCallForks->start->read() != 1);
		    FAIL_IF(moduleRouter->mStats.mCountCallForks->finish->read() != 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

/* ---------- Find best branch unit tests ---------- */

class AgentMock : public AgentInterface {
public:
	~AgentMock() override = default;
	std::shared_ptr<OutgoingAgent> getOutgoingAgent() override {
		return {};
	}
	std::shared_ptr<IncomingAgent> getIncomingAgent() override {
		return {};
	}
	std::shared_ptr<Http2Client> getFlexiApiClient() const noexcept override {
		return nullptr;
	}
	nta_agent_t* getSofiaAgent() const override {
		return nullptr;
	}
	void injectRequestEvent(unique_ptr<RequestSipEvent>&&) override {
	}
	unique_ptr<ResponseSipEvent> injectResponseEvent(unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	}
	unique_ptr<ResponseSipEvent> sendResponseEvent(unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	}
	const shared_ptr<sofiasip::SuRoot>& getRoot() const noexcept override {
		return mRoot;
	}

private:
	shared_ptr<sofiasip::SuRoot> mRoot = make_shared<sofiasip::SuRoot>();
};

class BranchInfoTest : public BranchInfo {
public:
	explicit BranchInfoTest(int mTestStatus) : mTestStatus(mTestStatus) {
	}
	virtual ~BranchInfoTest() {
	}

	int getStatus() override {
		return mTestStatus;
	}

private:
	int mTestStatus;
};

class ForkContextForTest : public ForkContextBase {
public:
	explicit ForkContextForTest(AgentInterface* agentMock)
	    : ForkContextBase(nullptr,
	                      agentMock,
	                      nullptr,
	                      std::weak_ptr<ForkContextListener>(),
	                      nullptr,
	                      std::weak_ptr<StatPair>(),
	                      sofiasip::MsgSipPriority::Normal,
	                      true) {
	}

	void addFakeBranch(const std::shared_ptr<BranchInfoTest>& br) {
		mWaitingBranches.push_back(br);
	}
	void onNewRegister([[maybe_unused]] const SipUri& dest,
	                   [[maybe_unused]] const std::string& uid,
	                   [[maybe_unused]] const std::shared_ptr<ExtendedContact>& newContact) override {};

	const char* getClassName() const override {
		return "ForkContextForTest";
	}

	shared_ptr<BranchInfo> pubFindBestBranch(bool avoid503And408) {
		return this->findBestBranch(avoid503And408);
	}
};

class FindBestBranchTest : public Test {
public:
	FindBestBranchTest(bool brFound, int statusCodeExpected, const vector<int>& statusList, bool avoid503And408 = true)
	    : mBrFound(brFound), mStatusCodeExpected(statusCodeExpected), mStatusList(statusList),
	      mAvoid503And408(avoid503And408) {
	}
	void operator()() override {
		ForkContextForTest fork{mAgentMock.get()};
		for_each(mStatusList.begin(), mStatusList.end(), [&fork](auto i) {
			const auto br = make_shared<BranchInfoTest>(i);
			fork.addFakeBranch(br);
		});

		const auto& br = fork.pubFindBestBranch(mAvoid503And408);

		BC_HARD_ASSERT_TRUE((br != nullptr) == mBrFound);
		if (br != nullptr) BC_HARD_ASSERT_CPP_EQUAL(br->getStatus(), mStatusCodeExpected);
	}

private:
	unique_ptr<AgentMock> mAgentMock = make_unique<AgentMock>();
	bool mBrFound;
	int mStatusCodeExpected;
	vector<int> mStatusList;
	bool mAvoid503And408;
	vector<int> mUrgentCode{};
};

class FindBestBranch6xxTest : public FindBestBranchTest {
public:
	FindBestBranch6xxTest() : FindBestBranchTest(true, 600, {420, 300, 603, 600, 301, 504}) {
	}
};

class FindBestBranch4xxTest : public FindBestBranchTest {
public:
	// 407 is more useful than 410, see SIP RFC.
	FindBestBranch4xxTest() : FindBestBranchTest(true, 407, {503, 505, 410, 400, 407, 401}) {
	}
};

class FindBestBranch3xxTest : public FindBestBranchTest {
public:
	FindBestBranch3xxTest() : FindBestBranchTest(true, 302, {503, 302, 410, 400, 407, 401, 300}) {
	}
};

class FindBestBranch2xxTest : public FindBestBranchTest {
public:
	FindBestBranch2xxTest() : FindBestBranchTest(true, 200, {204, 202, 603, 600, 200, 301, 504, 201}) {
	}
};

class FindBestBranchAvoid503Test : public FindBestBranchTest {
public:
	FindBestBranchAvoid503Test() : FindBestBranchTest(true, 500, {503, 500}) {
	}
};

class FindBestBranchAvoid408Test : public FindBestBranchTest {
public:
	FindBestBranchAvoid408Test() : FindBestBranchTest(true, 500, {503, 500, 408}) {
	}
};

class FindBestBranchDontAvoid503Test : public FindBestBranchTest {
public:
	FindBestBranchDontAvoid503Test() : FindBestBranchTest(true, 503, {503, 500}, false) {
	}
};

class FindBestBranchDontAvoid408Test : public FindBestBranchTest {
public:
	FindBestBranchDontAvoid408Test() : FindBestBranchTest(true, 408, {503, 500, 408}, false) {
	}
};

class FindBestBranchNoBranchConsidered : public FindBestBranchTest {
public:
	FindBestBranchNoBranchConsidered() : FindBestBranchTest(false, 0, {180, 100, 42}) {
	}
};

TestSuite _("ForkContext",
            {
                CLASSY_TEST(nullMaxForwardAndForkBasicContext),
                CLASSY_TEST(notRtpPortAndForkCallContext),
                CLASSY_TEST(globalOrderTestNoSql),
                CLASSY_TEST(run<FindBestBranch6xxTest>),
                CLASSY_TEST(run<FindBestBranch4xxTest>),
                CLASSY_TEST(run<FindBestBranch3xxTest>),
                CLASSY_TEST(run<FindBestBranch2xxTest>),
                CLASSY_TEST(run<FindBestBranchAvoid503Test>),
                CLASSY_TEST(run<FindBestBranchAvoid408Test>),
                CLASSY_TEST(run<FindBestBranchDontAvoid503Test>),
                CLASSY_TEST(run<FindBestBranchDontAvoid408Test>),
                CLASSY_TEST(run<FindBestBranchNoBranchConsidered>),
                CLASSY_TEST(messageDeliveryTimeoutTest),
                CLASSY_TEST(callForkTimeoutTest),
            },
            Hooks().beforeEach([] { responseReceived = false; }));

} // namespace
} // namespace flexisip::tester