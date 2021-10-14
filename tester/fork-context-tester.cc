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

#include <chrono>

#include <flexisip/agent.hh>
#include <flexisip/module-router.hh>

#include "tester.hh"
#include "utils/bellesip-utils.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;

using days = duration<int, ratio_multiply<ratio<24>, hours::period>>;

static su_root_t* root = nullptr;
static shared_ptr<Agent> agent = nullptr;
static bool responseReceived = false;

static string rawRequest{R"sip(MESSAGE sip:francois.grisez@sip.linphone.org SIP/2.0
Via: SIP/2.0/TLS [2a01:e0a:278:9f60:7a23:c334:1651:2503]:36676;branch=z9hG4bK.ChN0lTDpQ;rport
From: <sip:anthony.gauchy@sip.linphone.org>;tag=iXiKd6FuX
To: sip:francois.grisez@sip.linphone.org
CSeq: 20 MESSAGE
Call-ID: NISmf-QTgo
Max-Forwards: 70
Supported: replaces, outbound, gruu
Date: Wed, 06 Oct 2021 08:43:31 GMT
Content-Type: text/plain
Content-Length: 4
User-Agent: Linphone Desktop/4.3.0-beta-33-gc3ac9637 (Manjaro Linux, Qt 5.12.5) LinphoneCore/5.0.22-1-g8c5243994
Proxy-Authorization:  Digest realm="sip.linphone.org", nonce="1tMH5QAAAABVHBjkAADjdHyvMMkAAAAA", algorithm=SHA-256, opaque="+GNywA==", username="anthony.gauchy",  uri="sip:francois.grisez@sip.linphone.org", response="787857520cf0cd3f3f451ff7e867aa03536e8a7fed461fe2d14569d928f9296d", cnonce="UVZ7dG3P9Kx6j0na", nc=0000003f, qop=auth

\0st)sip"};

string rawResponse{R"sip(SIP/2.0 200 Ok
Via: SIP/2.0/TLS [2a01:e0a:278:9f60:7a23:c334:1651:2503]:36676;branch=z9hG4bK.ChN0lTDpQ;rport=36676
From: <sip:anthony.gauchy@sip.linphone.org>;tag=iXiKd6FuX
To: <sip:francois.grisez@sip.linphone.org>;tag=B2cE8pa
Call-ID: NISmf-QTgo
CSeq: 20 MESSAGE
Content-Length: 0)sip"};

/**
 * Empty implementation for testing purpose
 */
class BindListener : public ContactUpdateListener {
public:
	void onRecordFound(const shared_ptr<Record>& r) override {
	}
	void onError() override {
	}
	void onInvalid() override {
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
	}
};

static int beforeAll() {
	ForkMessageContextSociRepository::prepareConfiguration(
	    "mysql", "db='flexisip_messages' user='flexisip' password='flexisipass' host='localhost'", 10);

	return 0;
}

static void beforeEach() {
	ForkMessageContextSociRepository::getInstance()->deleteAll();
	responseReceived = false;
	root = su_root_create(nullptr);
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	RegistrarDb::resetDB();
	agent.reset();
	su_root_destroy(root);
}

static void nullMaxFrowardAndForkBasicContext() {
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_fork_context.conf").c_str());
	agent->loadConfig(cfg);

	auto registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
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
	RegistrarDb::get()->bind(user, participantContact, parameter, make_shared<BindListener>());

	// Starting Flexisip
	agent->start("", "");

	// Sending a request with Max-Forwards = 0
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP", [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 483, int, "%i");
			                            responseReceived = true;
		                            }
	                            }};
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
		su_root_step(agent->getRoot(), 100);
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
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_fork_context_media_relay.conf").c_str());
	agent->loadConfig(cfg);

	auto registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
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
	RegistrarDb::get()->bind(user, participantContact, parameter, make_shared<BindListener>());

	// Starting Flexisip
	agent->start("", "");

	// Sending a request with Max-Forwards = 0
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "UDP", [](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 500, int, "%i");
			                            responseReceived = true;
		                            }
	                            }};
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
		su_root_step(root, 100);
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

static void forkMessageContextSociRepositoryMysqlUnitTests() {
	auto request = std::make_shared<MsgSip>(msg_make(sip_default_mclass(), 0, rawRequest.c_str(), rawRequest.size()));
	auto reqSipEvent = std::make_shared<RequestSipEvent>(agent, request);

	// Save and find test
	auto nowPlusDays = system_clock::now() + days{7};
	std::time_t t = system_clock::to_time_t(nowPlusDays);
	ForkMessageContextDb fakeDbObject{1, 3, true, false, *localtime(&t)};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
	auto expectedFork =
	    ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                             shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);
	auto insertedUuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork);
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                                           shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);

	// Update and find test
	nowPlusDays = system_clock::now() + days{10};
	t = system_clock::to_time_t(nowPlusDays);
	fakeDbObject = ForkMessageContextDb{2, 10, false, true, *localtime(&t)};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"}; // We keep the same keys because they are not updated
	expectedFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                                        shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork, insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                                      shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);
}

static void forkMessageContextWithBranchesSociRepositoryMysqlUnitTests() {
	auto request = std::make_shared<MsgSip>(msg_make(sip_default_mclass(), 0, rawRequest.c_str(), rawRequest.size()));
	auto reqSipEvent = std::make_shared<RequestSipEvent>(agent, request);

	// Save and find with branch info test
	auto nowPlusDays = system_clock::now() + days{400};
	auto t = system_clock::to_time_t(nowPlusDays);
	auto fakeDbObject = ForkMessageContextDb{1.52, 5, false, true, *localtime(&t)};
	fakeDbObject.dbKeys = vector<string>{"key1"};
	BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
	BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
	BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	auto expectedFork =
	    ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                             shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);

	auto insertedUuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork);
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                                           shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);

	// Update and find with branch info test
	nowPlusDays = system_clock::now() + days{10};
	t = system_clock::to_time_t(nowPlusDays);
	fakeDbObject = ForkMessageContextDb{10, 1000, true, false, *localtime(&t)};
	fakeDbObject.dbKeys = vector<string>{"key1"}; // We keep the same keys because they are not updated
	branchInfoDb = BranchInfoDb{"contactUid", 3.0, rawRequest, rawResponse, false};
	branchInfoDb2 = BranchInfoDb{"contactUid2", 3.0, rawRequest, rawResponse, true};
	branchInfoDb3 = BranchInfoDb{"contactUid3", 3.42, rawRequest, rawResponse, false};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	expectedFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                                        shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork, insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
	                                      shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);
}

static void forkMessageContextSociRepositoryFullLoadMysqlUnitTests() {
	auto request = std::make_shared<MsgSip>(msg_make(sip_default_mclass(), 0, rawRequest.c_str(), rawRequest.size()));
	auto reqSipEvent = std::make_shared<RequestSipEvent>(agent, request);

	map<string, shared_ptr<ForkMessageContext>> expectedForks{};
	for (int i = 0; i < 10; i++) {
		auto nowPlusDays = system_clock::now() + days{400};
		auto t = system_clock::to_time_t(nowPlusDays);
		auto fakeDbObject = ForkMessageContextDb{1.52, 5, false, true, *localtime(&t)};
		fakeDbObject.dbKeys = vector<string>{"key"};
		BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
		BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
		BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
		fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
		auto expectedFork =
		    ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
		                             shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);
		auto insertedUuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork);
		expectedForks.insert(make_pair(insertedUuid, expectedFork));
	}

	auto dbForks = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	map<string, shared_ptr<ForkMessageContext>> actualForks{};

	for (auto dbFork : dbForks) {
		auto actualFork = ForkMessageContext::make(agent.get(), reqSipEvent, shared_ptr<ForkContextConfig>{},
		                                           shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
		actualForks.insert(make_pair(dbFork.uuid, actualFork));
	}

	if (actualForks.size() != expectedForks.size()) {
		BC_FAIL("[" << expectedForks.size() << "] expected forks but [" << actualForks.size() << "]found");
	}
	for (const auto& actualFork : actualForks) {
		auto it = expectedForks.find(actualFork.first);
		if (it != expectedForks.end()) {
			actualFork.second->assertEqual(it->second);
		} else {
			BC_FAIL("Forks with UUID " << actualFork.first << "not expected");
		}
	}
};

static test_t tests[] = {
    TEST_NO_TAG("Max forward 0 and ForkBasicContext leak", nullMaxFrowardAndForkBasicContext),
    TEST_NO_TAG("No RTP port available and ForkCallContext leak", notRtpPortAndForkCallContext),
    TEST_NO_TAG("Unit test fork message repository with mysql", forkMessageContextSociRepositoryMysqlUnitTests),
    TEST_NO_TAG("Unit test fork message with branches repository with mysql",
                forkMessageContextWithBranchesSociRepositoryMysqlUnitTests),
    TEST_NO_TAG("Unit test fork message repository with mysql, load at startup",
                forkMessageContextSociRepositoryFullLoadMysqlUnitTests),
};

test_suite_t fork_context_suite = {
    "Fork context", beforeAll, nullptr, beforeEach, afterEach, sizeof(tests) / sizeof(tests[0]), tests};
