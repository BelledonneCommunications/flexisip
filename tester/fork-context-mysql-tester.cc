/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022  Belledonne Communications SARL, All rights reserved.

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

static shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};

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

static int beforeAll() {
	ForkMessageContextSociRepository::prepareConfiguration(
	    "mysql", "db='flexisip_messages' user='belledonne' password='cOmmu2015nicatiOns' host='127.0.0.1'", 10);

	return 0;
}

static int afterAll() {
	ForkMessageContextSociRepository::getInstance()->deleteAll();

	return 0;
}

static void beforeEach() {
	ForkMessageContextSociRepository::getInstance()->deleteAll();
	root = make_shared<sofiasip::SuRoot>();
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	agent.reset();
	root.reset();
}

static void forkMessageContextSociRepositoryMysqlUnitTests() {
	// Save and find test
	auto nowPlusDays = system_clock::now() + days{7};
	std::time_t t = system_clock::to_time_t(nowPlusDays);
	ForkMessageContextDb fakeDbObject{1, 3, true, false, *gmtime(&t), rawRequest};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
	auto expectedFork =
	    ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{}, shared_ptr<ForkContextListener>{},
	                             shared_ptr<StatPair>{}, fakeDbObject);
	auto insertedUuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
	                                           shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);

	// Update and find test
	nowPlusDays = system_clock::now() + days{10};
	t = system_clock::to_time_t(nowPlusDays);
	fakeDbObject = ForkMessageContextDb{2, 10, false, true, *gmtime(&t), rawRequest};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"}; // We keep the same keys because they are not updated
	expectedFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
	                                        shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork->getDbObject(), insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
	                                      shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);
}

static void forkMessageContextWithBranchesSociRepositoryMysqlUnitTests() {
	// Save and find with branch info test
	auto nowPlusDays = system_clock::now() + days{400};
	auto t = system_clock::to_time_t(nowPlusDays);
	auto fakeDbObject = ForkMessageContextDb{1.52, 5, false, true, *gmtime(&t), rawRequest};
	fakeDbObject.dbKeys = vector<string>{"key1"};
	BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
	BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
	BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	auto expectedFork =
	    ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{}, shared_ptr<ForkContextListener>{},
	                             shared_ptr<StatPair>{}, fakeDbObject);

	auto insertedUuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
	                                           shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);

	// Update and find with branch info test
	nowPlusDays = system_clock::now() + days{10};
	t = system_clock::to_time_t(nowPlusDays);
	fakeDbObject = ForkMessageContextDb{10, 1000, true, false, *gmtime(&t), rawRequest};
	fakeDbObject.dbKeys = vector<string>{"key1"}; // We keep the same keys because they are not updated
	branchInfoDb = BranchInfoDb{"contactUid", 3.0, rawRequest, rawResponse, false};
	branchInfoDb2 = BranchInfoDb{"contactUid2", 3.0, rawRequest, rawResponse, true};
	branchInfoDb3 = BranchInfoDb{"contactUid3", 3.42, rawRequest, rawResponse, false};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	expectedFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
	                                        shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, fakeDbObject);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork->getDbObject(), insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
	                                      shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
	actualFork->assertEqual(expectedFork);
}

static void forkMessageContextSociRepositoryFullLoadMysqlUnitTests() {
	map<string, shared_ptr<ForkMessageContext>> expectedForks{};
	for (int i = 0; i < 10; i++) {
		auto nowPlusDays = system_clock::now() + days{400};
		auto t = system_clock::to_time_t(nowPlusDays);
		auto fakeDbObject = ForkMessageContextDb{1.52, 5, false, true, *gmtime(&t), rawRequest};
		fakeDbObject.dbKeys = vector<string>{"key"};
		BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
		BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
		BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
		fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
		auto expectedFork =
		    ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{}, shared_ptr<ForkContextListener>{},
		                             shared_ptr<StatPair>{}, fakeDbObject);
		auto insertedUuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
		expectedForks.insert(make_pair(insertedUuid, expectedFork));
	}

	auto dbForks = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	map<string, shared_ptr<ForkMessageContext>> actualForks{};

	for (auto dbFork : dbForks) {
		auto actualFork = ForkMessageContext::make(agent.get(), shared_ptr<ForkContextConfig>{},
		                                           shared_ptr<ForkContextListener>{}, shared_ptr<StatPair>{}, dbFork);
		actualForks.insert(make_pair(dbFork.uuid, actualFork));
		BC_ASSERT_TRUE(!dbFork.dbKeys.empty());
	}

	if (actualForks.size() != expectedForks.size()) {
		BC_FAIL("[" << expectedForks.size() << "] expected forks but [" << actualForks.size() << "]found");
	}
	for (const auto& actualFork : actualForks) {
		auto it = expectedForks.find(actualFork.first);
		if (it != expectedForks.end()) {
			actualFork.second->assertEqualMinimal(it->second);
		} else {
			BC_FAIL("Forks with UUID " << actualFork.first << "not expected");
		}
	}
}

static test_t tests[] = {
    TEST_NO_TAG("Unit test fork message repository with mysql", forkMessageContextSociRepositoryMysqlUnitTests),
    TEST_NO_TAG("Unit test fork message with branches repository with mysql",
                forkMessageContextWithBranchesSociRepositoryMysqlUnitTests),
    TEST_NO_TAG("Unit test fork message repository with mysql, load at startup",
                forkMessageContextSociRepositoryFullLoadMysqlUnitTests),
};

test_suite_t fork_context_mysql_suite = {
    "Fork context mysql", beforeAll, afterAll, beforeEach, afterEach, sizeof(tests) / sizeof(tests[0]), tests};
