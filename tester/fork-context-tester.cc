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

#include <chrono>

#include "flexisip/module-router.hh"
#include "flexisip/registrar/registar-listeners.hh"

#include "agent.hh"
#include "fork-context/fork-context-base.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/registrar-db.hh"
#include "tester.hh"
#include "utils/bellesip-utils.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

static bool responseReceived = false;

/**
 * Empty implementation for testing purpose
 */
class BindListener : public ContactUpdateListener {
public:
	void onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) override {
	}
	void onError(const SipStatus&) override {
	}
	void onInvalid(const SipStatus&) override {
	}
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
	}
};

static void nullMaxFrowardAndForkBasicContext() {
	auto root = make_shared<sofiasip::SuRoot>();
	// Agent initialization
	auto cfg = std::make_shared<ConfigManager>();
	cfg->load(bcTesterRes("config/flexisip_fork_context.conf"));

	auto* registrarConf = cfg->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	// Inserting a contact into the registrarDB.
	sofiasip::Home home{};
	SipUri user{"sip:participant1@127.0.0.1"};
	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_1";
	parameter.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameter.withGruu = true;
	auto participantContact = sip_contact_create(home.home(), (url_string_t*)user.str().c_str(), nullptr);
	auto registrarDb = make_shared<RegistrarDb>(root, cfg);
	registrarDb->bind(user, participantContact, parameter, make_shared<BindListener>());
	auto agent = make_shared<Agent>(root, cfg, make_shared<AuthDbBackendOwner>(cfg), registrarDb);

	// Starting Flexisip
	agent->start("", "");

	// Sending a request with Max-Forwards = 0
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP",
	                            [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 483, int, "%i");
			                            responseReceived = true;
		                            }
	                            },
	                            nullptr};
	bellesipUtils.sendRawRequest("OPTIONS sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	                             "Via: SIP/2.0/UDP 10.10.10.10:5060;rport;branch=z9hG4bK1439638806\r\n"
	                             "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	                             "To: <sip:participant1@127.0.0.1>\r\n"
	                             "Call-ID: 1053183492\r\n"
	                             "CSeq: 1 OPTIONS\r\n"
	                             "Contact: <sip:jehan-mac@192.168.1.8:5062>\r\n"
	                             "Max-Forwards: 0\r\n"
	                             "User-Agent: Linphone/3.3.99.10 (eXosip2/3.3.0)\r\n"
	                             "Content-Length: 0\r\n\r\n");

	// Flexisip and belle-sip loop, until response is received by the belle-sip stack.
	// If after 5s (MUST be inferior to ForkBasicContext timeout) nothing is received we break the loop and the test
	// should fail.
	auto beforePlus5 = system_clock::now() + 5s;
	while (!responseReceived && beforePlus5 >= system_clock::now()) {
		agent->getRoot()->step(100ms);
		bellesipUtils.stackSleep(100);
	}

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(responseReceived);
	if (moduleRouter) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountForks->start->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountForks->finish->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountBasicForks->start->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountBasicForks->finish->read(), 1, int, "%i");
	}
}

static void notRtpPortAndForkCallContext() {
	auto root = make_shared<sofiasip::SuRoot>();
	// Agent initialization
	auto cfg = std::make_shared<ConfigManager>();
	cfg->load(bcTesterRes("config/flexisip_fork_context_media_relay.conf"));

	auto* registrarConf = cfg->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("127.0.0.1");

	// Inserting a contact into the registrarDB.
	sofiasip::Home home{};
	SipUri user{"sip:participant1@127.0.0.1"};
	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_1";
	parameter.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameter.withGruu = true;
	auto participantContact = sip_contact_create(home.home(), (url_string_t*)user.str().c_str(), nullptr);
	auto registrarDb = make_shared<RegistrarDb>(root, cfg);
	registrarDb->bind(user, participantContact, parameter, make_shared<BindListener>());
	auto agent = make_shared<Agent>(root, cfg, make_shared<AuthDbBackendOwner>(cfg), registrarDb);

	// Starting Flexisip
	agent->start("", "");

	// Sending a request with Max-Forwards = 0
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP",
	                            [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 500, int, "%i");
			                            responseReceived = true;
		                            }
	                            },
	                            nullptr};
	bellesipUtils.sendRawRequest(
	    // Sip message
	    "INVITE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
	    "Via: SIP/2.0/UDP "
	    "10.23.17.117:22600;branch=z9hG4bK-d8754z-4d7620d2feccbfac-1---d8754z-;rport=4820;received=202.165.193.129\r\n"
	    "Max-Forwards: 70\r\n"
	    "Contact: <sip:bcheong@202.165.193.129:4820>\r\n"
	    "To: <sip:participant1@127.0.0.1>\r\n"
	    "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
	    "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	    "CSeq: 1 INVITE\r\n"
	    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
	    "c: application/sdp\r\n"
	    "Supported: replaces\r\n"
	    "Supported: 100rel\r\n"
	    "Authorization: Digest username=\"003332176\", realm=\"sip.ovh.net\", "
	    "nonce=\"24212965507cde726e8bc37e04686459\", uri=\"sip:sip.ovh.net\", "
	    "response=\"896e786e9c0525ca3085322c7f1bce7b\", algorithm=MD5, opaque=\"241b9fb347752f2\"\r\n"
	    "User-Agent: X-Lite 4 release 4.0 stamp 58832\r\n",
	    // Request body
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

	// Flexisip and belle-sip loop, until response is received by the belle-sip stack.
	// If after 5s (MUST be inferior to ForkBasicContext timeout) nothing is received we break the loop and the test
	// should fail.
	auto beforePlus5 = system_clock::now() + 5s;
	while (!responseReceived && beforePlus5 >= system_clock::now()) {
		root->step(100ms);
		bellesipUtils.stackSleep(100);
	}

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(responseReceived);
	if (moduleRouter) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountForks->start->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountForks->finish->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 1, int, "%i");
	}
}

/**
 * We send multiples message to a client with one idle device, to force the messages saving in DB.
 * Then we put the client back online and see if the messages are correctly delivered AND IN ORDER.
 * All along we check fork stats and client state.
 */
static void globalOrderTestNoSql() {
	SLOGD << "Step 1: Setup";
	auto server = make_shared<Server>("/config/flexisip_fork_context.conf");
	server->start();

	auto receiverClient = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server->getAgent());
	receiverClient->disconnect();

	uint isRequestAccepted = 0;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&isRequestAccepted](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            isRequestAccepted++;
		                            }
	                            },
	                            nullptr};

	SLOGD << "Step 2: Send messages, non-urgent first";
	uint nbOfMessages = 20;
	for (uint i = 1; i <= nbOfMessages; ++i) {
		std::string rawBody("C'est pas faux "s + to_string(i));
		rawBody.append("\r\n\r\n");
		bellesipUtils.sendRawRequest("MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
		                             "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
		                             "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		                             "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
		                             "CSeq: 20 MESSAGE\r\n"
		                             "Call-ID: Tvw6USHXYv"s +
		                                 to_string(i) +
		                                 "\r\n"
		                                 "Max-Forwards: 70\r\n"
		                                 "Route: <sip:127.0.0.1:5360;transport=tcp;lr>\r\n"
		                                 "Supported: replaces, outbound, gruu\r\n"
		                                 "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
		                                 "Content-Type: text/plain\r\n",
		                             rawBody);
		auto beforePlus2 = system_clock::now() + 2s;
		while (isRequestAccepted != i && beforePlus2 >= system_clock::now()) {
			server->getAgent()->getRoot()->step(10ms);
			bellesipUtils.stackSleep(10);
		}
	}

	SLOGD << "Step 3: Assert that fork is still present because device is offline. No db fork because no db.";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	CoreAssert asserter{receiverClient, server};
	BC_ASSERT_TRUE(asserter.wait([agent = server->getAgent(), &nbOfMessages] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->start->read() == nbOfMessages;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 0, int, "%i");

	SLOGD << "Step 4: Client REGISTER, then receive message";
	receiverClient->reconnect();
	BC_ASSERT_TRUE(asserter.wait([receiverClient, &nbOfMessages] {
		return receiverClient->getAccount()->getState() == linphone::RegistrationState::Ok &&
		       (uint)receiverClient->getCore()->getUnreadChatMessageCount() == nbOfMessages;
	}));

	SLOGD << "Step 5: Check messages order";
	auto messages = receiverClient->getChatMessages();
	uint order = 1;
	for (auto message : messages) {
		auto actual = message->getUtf8Text();
		string expected{"C'est pas faux "s + to_string(order) + "\r\n\r\n"};
		BC_ASSERT_CPP_EQUAL(actual, expected);
		order++;
	}
	BC_ASSERT_CPP_EQUAL(order - 1, nbOfMessages);

	SLOGD << "Step 6: Check fork stats";
	BC_ASSERT_TRUE(asserter.wait([agent = server->getAgent(), &nbOfMessages] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->finish->read() == nbOfMessages;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), nbOfMessages, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), nbOfMessages, int, "%i");
}

///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// UNIT TESTS findBestBranch//////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

class AgentMock : public AgentInterface {
public:
	~AgentMock() override = default;
	std::shared_ptr<OutgoingAgent> getOutgoingAgent() override {
		return std::shared_ptr<OutgoingAgent>();
	}
	std::shared_ptr<IncomingAgent> getIncomingAgent() override {
		return std::shared_ptr<IncomingAgent>();
	}
	nta_agent_t* getSofiaAgent() const override {
		return nullptr;
	}
	void injectRequestEvent([[maybe_unused]] const shared_ptr<RequestSipEvent>& ev) override {
	}
	void injectResponseEvent([[maybe_unused]] const shared_ptr<ResponseSipEvent>& ev) override {
	}
	void sendResponseEvent([[maybe_unused]] const shared_ptr<ResponseSipEvent>& ev) override {
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
	ForkContextForTest(AgentInterface* agentMock)
	    : ForkContextBase(nullptr,
	                      agentMock,
	                      nullptr,
	                      nullptr,
	                      std::weak_ptr<ForkContextListener>(),
	                      std::weak_ptr<StatPair>(),
	                      sofiasip::MsgSipPriority::Normal,
	                      true) {
	}

	void addFakeBranch(const std::shared_ptr<BranchInfoTest>& br) {
		mWaitingBranches.push_back(br);
	}
	void onNewRegister([[maybe_unused]] const SipUri& dest,
	                   [[maybe_unused]] const std::string& uid,
	                   [[maybe_unused]] const std::shared_ptr<ExtendedContact>& newContact) override{};

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

///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

namespace {
TestSuite _("Fork context",
            {
                TEST_NO_TAG("Max forward 0 and ForkBasicContext leak", nullMaxFrowardAndForkBasicContext),
                TEST_NO_TAG("No RTP port available and ForkCallContext leak", notRtpPortAndForkCallContext),
                TEST_NO_TAG("Fork message context with fork late and no database : retention and order check",
                            globalOrderTestNoSql),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranch6xxTest>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranch4xxTest>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranch3xxTest>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranch2xxTest>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranchAvoid503Test>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranchAvoid408Test>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranchDontAvoid503Test>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranchDontAvoid408Test>),
                TEST_NO_TAG_AUTO_NAMED(run<FindBestBranchNoBranchConsidered>),
            },
            Hooks().beforeEach([] { responseReceived = false; }));
}
