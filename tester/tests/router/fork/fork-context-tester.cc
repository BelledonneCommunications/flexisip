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

#include "agent.hh"
#include "flexisip/module-router.hh"
#include "fork-context/fork-context-base.hh"
#include "fork-context/message-kind.hh"
#include "registrar/binding-parameters.hh"
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

const std::map<std::string, std::string> kConfig{
    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
    {"module::DoSProtection/enabled", "false"},
    {"module::MediaRelay/enabled", "false"},
    {"module::Router/fork-late", "true"},
    {"module::Router/message-database-enabled", "false"},
    {"module::Registrar/reg-domains", "localhost 127.0.0.1 sip.test.org"},
};

void nullMaxForwardAndForkBasicContext() {
	Server proxy{kConfig};
	proxy.start();

	const auto& registrarDb = proxy.getRegistrarDb();
	ContactInserter inserter{*registrarDb};
	inserter.withGruu(true).setExpire(1000s).setAor("sip:participant1@localhost").insert();

	bool responseReceived = false;
	BellesipUtils client{
	    "127.0.0.1",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 483);
			    responseReceived = true;
		    }
	    },
	    nullptr,
	};

	stringstream request{};
	request << "OPTIONS sip:participant1@localhost SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP localhost:5060;rport;branch=z9hG4bK1439638806\r\n"
	        << "From: <sip:participant2@localhost>;tag=465687829\r\n"
	        << "To: <sip:participant1@localhost>\r\n"
	        << "Call-ID: stub-call-id\r\n"
	        << "CSeq: 1 OPTIONS\r\n"
	        << "Route: <sip:127.0.0.1:" << proxy.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Contact: <sip:participant1@localhost>\r\n"
	        << "Max-Forwards: 0\r\n"
	        << "User-Agent: BelleSipUtils\r\n"
	        << "Content-Length: 0\r\n\r\n";
	client.sendRawRequest(request.str());

	CoreAssert{proxy, client}.wait([&] { return LOOP_ASSERTION(responseReceived); }).hard_assert_passed();
	BC_HARD_ASSERT(responseReceived == true);

	const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->finish->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->finish->read(), 1);
}

void notEnoughRtpPortAndForkCallContext() {
	Server proxy{kConfig};
	proxy.setConfigParameter({"module::Router/fork-late", "false"});
	proxy.setConfigParameter({"module::MediaRelay/enabled", "true"});
	// Only 2 ports are given but 4 are needed.
	proxy.setConfigParameter({"module::MediaRelay/sdp-port-range", "1024-1026"});
	proxy.start();

	const auto& registrarDb = proxy.getRegistrarDb();
	ContactInserter inserter{*registrarDb};
	inserter.withGruu(true).setExpire(1000s).setAor("sip:participant1@localhost").insert();

	bool responseReceived = false;
	BellesipUtils client{
	    "127.0.0.1",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 500);
			    responseReceived = true;
		    }
	    },
	    nullptr,
	};

	stringstream request{};
	request << "INVITE sip:participant1@localhost SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP localhost:5060;rport;branch=z9hG4bK1439638806\r\n"
	        << "From: <sip:participant2@localhost>;tag=465687829\r\n"
	        << "To: <sip:participant1@localhost>\r\n"
	        << "Call-ID: stub-call-id\r\n"
	        << "CSeq: 20 INVITE\r\n"
	        << "Route: <sip:127.0.0.1:" << proxy.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Contact: <sip:participant1@localhost>\r\n"
	        << "Max-Forwards: 70\r\n"
	        << "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
	        << "Content-Type: application/sdp\r\n"
	        << "User-Agent: BelleSipUtils\r\n\r\n";
	stringstream body{};
	body << "v=0\r\n"
	     << "o=participant1 3102 279 IN IP4 127.0.0.1\r\n"
	     << "s=Talk\r\n"
	     << "c=IN IP4 127.0.0.1\r\n"
	     << "t=0 0\r\n"
	     << "m=audio 7078 RTP/AVP 0 8\r\n"
	     << "m=video 8078 RTP/AVP 99 97 98\r\n"
	     << "c=IN IP4 127.0.0.1\r\n"
	     << "b=AS:380\r\n"
	     << "a=rtpmap:99 MP4V-ES/90000\r\n"
	     << "a=fmtp:99 profile-level-id=3\r\n";
	client.sendRawRequest(request.str(), body.str());

	CoreAssert{proxy, client}.wait([&] { return LOOP_ASSERTION(responseReceived); }).hard_assert_passed();
	BC_HARD_ASSERT(responseReceived == true);

	const auto& router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->finish->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountCallForks->finish->read(), 1);
}

void referRequestUsesForkBasicContext() {
	Server proxy{kConfig};
	proxy.start();

	bool responseReceived = false;
	BellesipUtils client{
	    "127.0.0.1",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 200);
			    responseReceived = true;
		    }
	    },
	    nullptr,
	};

	const auto& registrarDb = proxy.getRegistrarDb();
	ContactInserter inserter{*registrarDb};
	inserter.withGruu(true)
	    .setExpire(1000s)
	    .setAor("sip:participant1@localhost")
	    .insert({"sip:participant1@127.0.0.1:"s + to_string(client.getListeningPort()) + ";transport=tcp"});

	stringstream request{};
	request << "REFER sip:participant1@localhost SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP localhost:5060;rport;branch=z9hG4bK1439638806\r\n"
	        << "From: <sip:participant2@localhost>;tag=465687829\r\n"
	        << "To: <sip:participant1@localhost>\r\n"
	        << "Call-ID: stub-call-id\r\n"
	        << "CSeq: 1 REFER\r\n"
	        << "Route: <sip:127.0.0.1:" << proxy.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Contact: <sip:participant1@localhost>\r\n"
	        << "Refer-To: <sip:stub@localhost>;text\r\n"
	        << "Max-Forwards: 70\r\n"
	        << "User-Agent: BelleSipUtils\r\n"
	        << "Content-Length: 0\r\n\r\n";
	client.sendRawRequest(request.str());

	CoreAssert{proxy, client}.wait([&] { return LOOP_ASSERTION(responseReceived); }).hard_assert_passed();
	BC_HARD_ASSERT(responseReceived == true);

	const auto router = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountForks->finish->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountBasicForks->finish->read(), 1);
}

/**
 * We send multiple messages to a client with one idle device. Then we put the client back online and see if the
 * messages are correctly delivered AND IN ORDER. All along we check fork stats and client state.
 */
void globalOrderTestNoSql() {
	SLOGD << "Step 1: Setup";
	Server server{kConfig};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto receiver = builder.build("sip:receiver@sip.test.org");
	receiver.disconnect();

	auto isRequestAccepted = 0U;
	BellesipUtils sender{
	    "127.0.0.1",
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
		string body{"C'est pas faux "s + to_string(i) + "\r\n\r\n"};
		stringstream request{};
		request << "MESSAGE sip:receiver@sip.test.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
		        << "From: <sip:sender@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		        << "To: <sip:receiver@sip.test.org>\r\n"
		        << "CSeq: 20 MESSAGE\r\n"
		        << "Call-ID: stub-call-id-" << i << "\r\n"
		        << "Max-Forwards: 70\r\n"
		        << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu\r\n"
		        << "Content-Type: text/plain\r\n"
		        << "Content-Length: " << body.size() << "\r\n\r\n";
		sender.sendRawRequest(request.str(), body);

		CoreAssert{server, sender}.wait([&] { return LOOP_ASSERTION(isRequestAccepted == i); }).hard_assert_passed();
	}

	SLOGD << "Step 3: Assert that fork is still present because device is offline, no db fork because no db";
	const auto router = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	CoreAssert asserter{server, receiver};
	asserter
	    .wait([&] {
		    return LOOP_ASSERTION(router->mStats.mForkStats->mCountMessageForks->start->read() == nbOfMessages);
	    })
	    .hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->start->read(), 0);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->finish->read(), 0);

	SLOGD << "Step 4: Client REGISTER, then receive message";
	receiver.reconnect();
	asserter
	    .wait([&receiver, &nbOfMessages] {
		    FAIL_IF(receiver.getAccount()->getState() != linphone::RegistrationState::Ok);
		    FAIL_IF(static_cast<unsigned int>(receiver.getCore()->getUnreadChatMessageCount()) != nbOfMessages);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	SLOGD << "Step 5: Check messages order";
	auto messages = receiver.getChatMessages();
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
	    .wait([&] {
		    return LOOP_ASSERTION(router->mStats.mForkStats->mCountMessageForks->finish->read() == nbOfMessages);
	    })
	    .hard_assert_passed();
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->start->read(), 0);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->start->read(), nbOfMessages);
	BC_ASSERT_CPP_EQUAL(router->mStats.mForkStats->mCountMessageForks->finish->read(), nbOfMessages);
}

/**
 * The main goal of this test is to ensure correct enforcement of the "message-delivery-timeout" configuration. This
 * means that after the specified duration of "message-delivery-timeout" seconds, the ForkMessageContext must be
 * destroyed, and the message should be forgotten, even if it was not delivered to all devices.
 *
 * To execute this test, the following steps are performed:
 *   1 - The test is initiated by sending a message from the caller to the callee, who has two clients: one online and
 *       one offline.
 *   2 - Simultaneously, a call is initiated between the caller and the callee.
 *   3 - Upon completion of the test and after the designated "message-delivery-timeout" period has elapsed, we verify
 *       that the ForkMessageContext is destroyed while the ForkCallContext remains active.
 */
void messageDeliveryTimeoutTest() {
	Server server{kConfig};
	server.setConfigParameter({"module::Router/message-delivery-timeout", "1"});
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientVoip = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	calleeIdleClientVoip.disconnect();
	BC_ASSERT_PTR_NOT_NULL(callerClient.callWithEarlyCancel(calleeClient));

	const auto chatroom = callerClient.chatroomBuilder().build({calleeClient.getMe()});
	chatroom->createMessageFromUtf8("test")->send();

	const auto router = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	CoreAssert{server, callerClient, calleeClient, calleeIdleClientVoip}
	    .wait([&router] {
		    // The client may send an IMDN, so we cannot explicitly check that start value equals 1.
		    FAIL_IF(router->mStats.mForkStats->mCountMessageForks->start->read() < 1);
		    // All ForkMessageContexts must be destroyed, since they should only live for one second.
		    FAIL_IF(router->mStats.mForkStats->mCountMessageForks->finish->read() !=
		            router->mStats.mForkStats->mCountMessageForks->start->read());

		    // ForkCallContext must still be present, waiting for delivery (one created, zero finished).
		    FAIL_IF(router->mStats.mForkStats->mCountCallForks->start->read() != 1);
		    FAIL_IF(router->mStats.mForkStats->mCountCallForks->finish->read() != 0);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

/**
 * The main goal of this test is to ensure correct enforcement of the "call-fork-timeout" configuration. This means that
 * after the specified duration of "call-fork-timeout" seconds, the ForkCallContext must be destroyed, and the call
 * should be forgotten, even if it was not delivered to all devices.
 *
 * To execute this test, the following steps are performed:
 *   1 - The test is initiated by sending a message from the caller to the callee, who has two clients: one online and
 *       one offline.
 *   2 - Simultaneously, a call is initiated between the caller and the callee
 *   3 - Upon completion of the test and after the designated "call-fork-timeout" period has elapsed, we verify
 *       that the ForkCallContext is destroyed while the ForkMessageContext remains active.
 */
void callForkTimeoutTest() {
	Server server{kConfig};
	server.setConfigParameter({"module::Router/call-fork-timeout", "1"});
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientVoip = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	calleeIdleClientVoip.disconnect();

	// Quick call without asserting, just to create a ForkCall.
	const auto callParams = callerClient.getCore()->createCallParams(nullptr);
	const auto addressWithoutGr = calleeClient.getAccount()->getContactAddress()->clone();
	addressWithoutGr->removeUriParam("gr");
	const auto callerCall = callerClient.getCore()->inviteAddressWithParams(addressWithoutGr, callParams);
	callerCall->terminate();

	const auto chatroom = callerClient.chatroomBuilder().build({calleeClient.getMe()});
	chatroom->createMessageFromUtf8("test")->send();

	const auto router = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModuleByRole("Router"));
	BC_HARD_ASSERT(router != nullptr);

	CoreAssert{server, callerClient, calleeClient, calleeIdleClientVoip}
	    .wait([&router] {
		    // The client may send an IMDN, so we cannot explicitly check that start value equals 1.
		    FAIL_IF(router->mStats.mForkStats->mCountMessageForks->start->read() < 1);
		    // At least 1 message must be still present.
		    FAIL_IF(router->mStats.mForkStats->mCountMessageForks->finish->read() ==
		            router->mStats.mForkStats->mCountMessageForks->start->read());

		    // ForkCallContext must be destroyed, since they should only live for one second.
		    FAIL_IF(router->mStats.mForkStats->mCountCallForks->start->read() != 1);
		    FAIL_IF(router->mStats.mForkStats->mCountCallForks->finish->read() != 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

/* ---------- Start of "find best branch" unit tests ---------- */

class AgentMock : public AgentInterface {
public:
	~AgentMock() override = default;
	std::shared_ptr<OutgoingAgent> getOutgoingAgent() override {
		return {};
	}
	std::shared_ptr<IncomingAgent> getIncomingAgent() override {
		return {};
	}
	nta_agent_t* getSofiaAgent() const override {
		return nullptr;
	}
	void injectRequestEvent(unique_ptr<RequestSipEvent>&&) override {}
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
	explicit BranchInfoTest(int mTestStatus) : mTestStatus(mTestStatus){};
	~BranchInfoTest() override = default;
	int getStatus() override {
		return mTestStatus;
	}

private:
	int mTestStatus;
};

class ForkContextForTest : public ForkContextBase {
public:
	explicit ForkContextForTest(AgentInterface* agentMock)
	    : ForkContextBase(agentMock,
	                      nullptr,
	                      std::weak_ptr<InjectorListener>(),
	                      std::weak_ptr<ForkContextListener>(),
	                      nullptr,
	                      std::weak_ptr<StatPair>(),
	                      sofiasip::MsgSipPriority::Normal,
	                      true){};

	void addFakeBranch(const std::shared_ptr<BranchInfoTest>& br) {
		mWaitingBranches.push_back(br);
	}
	void onNewRegister(const SipUri&, const std::string&, const std::shared_ptr<ExtendedContact>&) override {};
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
	      mAvoid503And408(avoid503And408) {}
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
};

class FindBestBranch6xxTest : public FindBestBranchTest {
public:
	FindBestBranch6xxTest() : FindBestBranchTest(true, 600, {420, 300, 603, 600, 301, 504}){};
};

class FindBestBranch4xxTest : public FindBestBranchTest {
public:
	// 407 is more useful than 410, see SIP RFC.
	FindBestBranch4xxTest() : FindBestBranchTest(true, 407, {503, 505, 410, 400, 407, 401}){};
};

class FindBestBranch3xxTest : public FindBestBranchTest {
public:
	FindBestBranch3xxTest() : FindBestBranchTest(true, 302, {503, 302, 410, 400, 407, 401, 300}){};
};

class FindBestBranch2xxTest : public FindBestBranchTest {
public:
	FindBestBranch2xxTest() : FindBestBranchTest(true, 200, {204, 202, 603, 600, 200, 301, 504, 201}){};
};

class FindBestBranchAvoid503Test : public FindBestBranchTest {
public:
	FindBestBranchAvoid503Test() : FindBestBranchTest(true, 500, {503, 500}){};
};

class FindBestBranchAvoid408Test : public FindBestBranchTest {
public:
	FindBestBranchAvoid408Test() : FindBestBranchTest(true, 500, {503, 500, 408}){};
};

class FindBestBranchDontAvoid503Test : public FindBestBranchTest {
public:
	FindBestBranchDontAvoid503Test() : FindBestBranchTest(true, 503, {503, 500}, false){};
};

class FindBestBranchDontAvoid408Test : public FindBestBranchTest {
public:
	FindBestBranchDontAvoid408Test() : FindBestBranchTest(true, 408, {503, 500, 408}, false){};
};

class FindBestBranchNoBranchConsidered : public FindBestBranchTest {
public:
	FindBestBranchNoBranchConsidered() : FindBestBranchTest(false, 0, {180, 100, 42}){};
};

/* ---------- End of "find best branch" unit tests ---------- */

void missingUserInfoInFromOrToHeaderWhenCreatingMessageKindInstance() {
	sip_to_t to = {.a_url = {url_t{.url_user = "chatroom-id-of-the-chatroom"}}};
	sip_from_t from = {.a_url = {url_t{.url_user = nullptr}}};
	sip_request_t request = {.rq_method = sip_method_message};
	sip_t sip{.sip_request = &request, .sip_from = &from, .sip_to = &to};
	MessageKind kind{sip, sofiasip::MsgSipPriority::Normal};
	BC_ASSERT_ENUM_EQUAL(kind.getCardinality(), MessageKind::Cardinality::ToConferenceServer);
	BC_ASSERT_ENUM_EQUAL(kind.getPriority(), sofiasip::MsgSipPriority::Normal);
	BC_ASSERT_CPP_EQUAL(kind.getConferenceId().value_or(""), "id-of-the-chatroom");
}

TestSuite _{
    "ForkContext",
    {
        CLASSY_TEST(nullMaxForwardAndForkBasicContext),
        CLASSY_TEST(notEnoughRtpPortAndForkCallContext),
        CLASSY_TEST(referRequestUsesForkBasicContext),
        CLASSY_TEST(globalOrderTestNoSql),
        CLASSY_TEST(messageDeliveryTimeoutTest),
        CLASSY_TEST(callForkTimeoutTest),
        CLASSY_TEST(run<FindBestBranch6xxTest>),
        CLASSY_TEST(run<FindBestBranch4xxTest>),
        CLASSY_TEST(run<FindBestBranch3xxTest>),
        CLASSY_TEST(run<FindBestBranch2xxTest>),
        CLASSY_TEST(run<FindBestBranchAvoid503Test>),
        CLASSY_TEST(run<FindBestBranchAvoid408Test>),
        CLASSY_TEST(run<FindBestBranchDontAvoid503Test>),
        CLASSY_TEST(run<FindBestBranchDontAvoid408Test>),
        CLASSY_TEST(run<FindBestBranchNoBranchConsidered>),
        CLASSY_TEST(missingUserInfoInFromOrToHeaderWhenCreatingMessageKindInstance),
    },
};

} // namespace
} // namespace flexisip::tester