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
#include <memory>
#include <optional>
#include <random>
#include <utility>

#include "flexisip/logmanager.hh"
#include "flexisip/module-router.hh"
#include "fork-context/fork-context-factory.hh"
#include "fork-context/fork-message-context-db-proxy.hh"
#include "fork-context/fork-message-context-soci-repository.hh"
#include "router/fork-manager.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/bellesip-utils.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/mysql-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

using days = duration<int, ratio_multiply<ratio<24>, hours::period>>;

optional<MysqlServer> mysqlServer = nullopt;
const weak_ptr<ForkContextListener> nullListener{};

string rawRequest{R"sip(MESSAGE sip:francois.grisez@sip.test.org SIP/2.0
Via: SIP/2.0/TLS [2a01:e0a:278:9f60:7a23:c334:1651:2503]:36676;branch=z9hG4bK.ChN0lTDpQ
From: <sip:anthony.gauchy@sip.test.org>;tag=iXiKd6FuX
To: sip:francois.grisez@sip.test.org
CSeq: 20 MESSAGE
Call-ID: NISmf-QTgo
Max-Forwards: 70
Supported: replaces, outbound, gruu
Date: Wed, 06 Oct 2021 08:43:31 GMT
User-Agent: BelleSipUtils
Content-Type: text/plain
Content-Length: 4

\0st)sip"};

string rawResponse{R"sip(SIP/2.0 200 Ok
Via: SIP/2.0/TLS [2a01:e0a:278:9f60:7a23:c334:1651:2503]:36676;branch=z9hG4bK.ChN0lTDpQ
From: <sip:anthony.gauchy@sip.test.org>;tag=iXiKd6FuX
To: <sip:francois.grisez@sip.test.org>;tag=B2cE8pa
CSeq: 20 MESSAGE
Call-ID: NISmf-QTgo
Content-Length: 0
)sip"};

/**
 * Flexisip server configuration.
 */
const map<string, string> configuration{
    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
    {"module::DoSProtection/enabled", "false"},
    {"module::Router/fork-late", "true"},
    {"module::Router/message-fork-late", "true"},
    {"module::Router/message-database-enabled", "true"},
    {"module::Router/message-database-backend", "mysql"},
    {"module::Router/message-database-connection-string",
     "db=flexisip_messages user='belledonne' password='cOmmu2015nicatiOns' host=127.0.0.1"},
    {"module::Registrar/reg-domains", "sip.test.org 127.0.0.1"},
};

// Use it to create an instance before the configuration is overridden by a reload.
void forceSociRepositoryInstantiation() {
	mysqlServer->waitReady();
	ForkMessageContextSociRepository::getInstance();
}

void forkMessageContextSociRepositoryMysql() {
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	const auto forkFactory = moduleRouter->getForkManager()->getFactory();
	Random random{tester::random::seed()};
	auto timestampGenerator = random.timestamp();

	// Save and find test.
	auto targetTime = timestampGenerator.generate();
	SLOGD << "Target time: " << targetTime;
	BC_ASSERT_PTR_NOT_NULL(gmtime(&targetTime));

	ForkMessageContextDb fakeDbObject{1, 3, true, *gmtime(&targetTime), rawRequest, MsgSipPriority::NonUrgent};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
	auto expectedFork = forkFactory->restoreForkMessageContext(fakeDbObject, nullListener);
	mysqlServer->waitReady();
	const auto insertedUuid =
	    ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = forkFactory->restoreForkMessageContext(dbFork, nullListener);
	BC_ASSERT_CPP_EQUAL(string{asctime(&dbFork.expirationDate)}, string{asctime(&fakeDbObject.expirationDate)});
	actualFork->assertEqual(expectedFork);

	// Update and find test.
	targetTime = timestampGenerator.generate();
	fakeDbObject = ForkMessageContextDb{2, 10, false, *gmtime(&targetTime), rawRequest, MsgSipPriority::Urgent};
	// We keep the same keys because they are not updated.
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
	expectedFork = forkFactory->restoreForkMessageContext(fakeDbObject, nullListener);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork->getDbObject(),
	                                                                          insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = forkFactory->restoreForkMessageContext(fakeDbObject, nullListener);
	actualFork->assertEqual(expectedFork);
}

void forkMessageContextWithBranchesSociRepositoryMysql() {
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	const auto forkFactory = moduleRouter->getForkManager()->getFactory();
	Random random{tester::random::seed()};
	Random::TimestampGenerator timestampGenerator = random.timestamp();

	// Save and find with branch info test.
	auto targetTime = timestampGenerator.generate();
	auto fakeDbObject = ForkMessageContextDb{1.52, 5, false, *gmtime(&targetTime), rawRequest, MsgSipPriority::Normal};
	fakeDbObject.dbKeys = vector<string>{"key1"};
	BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
	BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
	BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	auto expectedFork = forkFactory->restoreForkMessageContext(fakeDbObject, nullListener);

	mysqlServer->waitReady();
	const auto insertedUuid =
	    ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = forkFactory->restoreForkMessageContext(dbFork, nullListener);
	actualFork->assertEqual(expectedFork);

	// Update and find with branch info test
	targetTime = timestampGenerator.generate();
	fakeDbObject = ForkMessageContextDb{10, 1000, true, *gmtime(&targetTime), rawRequest, MsgSipPriority::Emergency};
	fakeDbObject.dbKeys = vector<string>{"key1"}; // We keep the same keys because they are not updated
	branchInfoDb = BranchInfoDb{"contactUid", 3.0, rawRequest, rawResponse, false};
	branchInfoDb2 = BranchInfoDb{"contactUid2", 3.0, rawRequest, rawResponse, true};
	branchInfoDb3 = BranchInfoDb{"contactUid3", 3.42, rawRequest, rawResponse, false};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	expectedFork = forkFactory->restoreForkMessageContext(fakeDbObject, nullListener);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork->getDbObject(),
	                                                                          insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = forkFactory->restoreForkMessageContext(dbFork, nullListener);
	actualFork->assertEqual(expectedFork);
}

void forkMessageContextSociRepositoryFullLoadMysql() {
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();
	const auto moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	const auto forkFactory = moduleRouter->getForkManager()->getFactory();
	Random random{tester::random::seed()};
	auto timestampGenerator = random.timestamp();

	auto integerGenerator = random.integer<int>(10, 20);
	const auto nbForks = integerGenerator.generate();
	map<string, shared_ptr<ForkMessageContext>> expectedForks{};
	for (int forkId = 0; forkId < nbForks; forkId++) {
		auto targetTime = timestampGenerator.generate();
		auto fakeFork = ForkMessageContextDb{1., 5, false, *gmtime(&targetTime), rawRequest, MsgSipPriority::NonUrgent};

		auto stringGenerator = random.string();
		auto stringLengthGenerator = random.integer<size_t>(1, 255);
		const auto nbDbKeys = integerGenerator.generate();
		for (int dbKeyId = 0; dbKeyId < nbDbKeys; dbKeyId++)
			fakeFork.dbKeys.push_back(stringGenerator.generate(stringLengthGenerator.generate()));

		const auto nbBranchInfo = integerGenerator.generate();
		auto priorityGenerator = random.real<double>(1.0, 5.0);
		for (int branchInfoId = 0; branchInfoId < nbBranchInfo; branchInfoId++)
			fakeFork.dbBranches.emplace_back("contactUID-" + to_string(branchInfoId), priorityGenerator.generate(),
			                                 rawRequest, rawResponse, random.boolean().generate());

		const auto fork = forkFactory->restoreForkMessageContext(fakeFork, nullListener);
		mysqlServer->waitReady();
		const auto uuid = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(fork->getDbObject());
		expectedForks.insert({uuid, fork});
	}

	auto dbForks = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	BC_HARD_ASSERT_CPP_EQUAL(dbForks.size(), expectedForks.size());

	// Verify order of dbForks (must be ordered by expiration date).
	time_t lastExpirationTime{};
	for (auto& dbFork : dbForks) {
		const auto expirationTime = std::mktime(&dbFork.expirationDate);
		BC_HARD_ASSERT(difftime(expirationTime, lastExpirationTime) >= 0.);
		lastExpirationTime = expirationTime;
	}

	// Compare uuid and dbKeys.
	for (auto& actualFork : dbForks) {
		auto expectedForkIt = expectedForks.find(actualFork.uuid);
		if (expectedForkIt == expectedForks.end()) {
			BC_FAIL("uuid from dbForks not found in expectedForks map");
			continue;
		}

		auto actualKeys = forkFactory->restoreForkMessageContextDbProxy(actualFork, nullListener)->getKeys();
		auto expectedKeys = expectedForkIt->second->getKeys();
		BC_HARD_ASSERT_CPP_EQUAL(actualKeys.size(), expectedKeys.size());

		sort(actualKeys.begin(), actualKeys.end());
		sort(expectedKeys.begin(), expectedKeys.end());
		for (size_t keyId = 0; keyId < actualKeys.size(); keyId++)
			BC_HARD_ASSERT_CPP_EQUAL(actualKeys[keyId], expectedKeys[keyId]);
	}
}

/**
 * Send a message to a client with one idle device, to force the message to be saved in DB.
 * At this point we assert that the message saved in DB is the same as the one sent.
 * Then we put the client back online and see if the message is correctly delivered.
 * All along, we check fork stats and client state.
 */
void globalTest() {
	SLOGD << "Step 1: Setup";
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto receiverClient = builder.build("sip:provencal_le_gaulois@sip.test.org");
	receiverClient.disconnect();

	bool isRequestAccepted = false;
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&isRequestAccepted](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 202);
			    isRequestAccepted = true;
		    }
	    },
	    nullptr,
	};

	SLOGD << "Step 2: Send message";
	string body(100000, 'a');
	body.insert(0, "C'est pas faux\r\n\r\n");
	stringstream request{};
	request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1\r\n"
	        << "From: <sip:kijou@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	        << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	        << "CSeq: 20 MESSAGE\r\n"
	        << "Call-ID: Tvw6USHXYv\r\n"
	        << "Max-Forwards: 70\r\n"
	        << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Supported: replaces, outbound, gruu\r\n"
	        << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	        << "Content-Type: text/plain\r\n"
	        << "Content-Length: " << body.size() << "\r\n\r\n";
	belleSipUtils.sendRawRequest(request.str(), body);

	CoreAssert asserter{server, belleSipUtils, receiverClient};
	asserter.wait([&isRequestAccepted]() { return LOOP_ASSERTION(isRequestAccepted); }).assert_passed();

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);

	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 1);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 1);

	SLOGD << "Step 4: Check that request in DB is the same that request sent";
	const auto allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	if (allMessages.size() == 1) {
		const auto requestInDb =
		    ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(allMessages.cbegin()->uuid).request;
		// We only compare body because headers can be modified a bit by the proxy
		if (requestInDb.find(body) == string::npos) BC_FAIL("Body not found");
	} else BC_FAIL("No message in DB, or too much");

	SLOGD << "Step 5: Client REGISTER, then receive message";
	receiverClient.reconnect();
	asserter
	    .wait([&receiverClient] {
		    return LOOP_ASSERTION(receiverClient.getAccount()->getState() == RegistrationState::Ok &&
		                          receiverClient.getCore()->getUnreadChatMessageCount() == 1);
	    })
	    .assert_passed();

	SLOGD << "Step 6: Client REGISTER, then receive message";
	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read() == 1);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 2);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 2);
}

void globalTestMultipleDevices() {
	SLOGD << "Step 1: Setup";
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();

	CoreAssert asserter{server};
	ClientBuilder builder{*server.getAgent()};
	vector<shared_ptr<CoreClient>> clientOnDevices{};
	for (int i = 0; i < 3; ++i) {
		asserter.registerSteppable(clientOnDevices.emplace_back(builder.make("sip:provencal_le_gaulois@sip.test.org")));
	}
	vector<shared_ptr<CoreClient>> clientOffDevices1{};
	for (int i = 0; i < 3; ++i) {
		const auto& client = builder.make("sip:provencal_le_gaulois@sip.test.org");
		client->disconnect();
		asserter.registerSteppable(clientOffDevices1.emplace_back(client));
	}
	vector<shared_ptr<CoreClient>> clientOffDevices2{};
	for (int i = 0; i < 3; ++i) {
		const auto& client = builder.make("sip:provencal_le_gaulois@sip.test.org");
		client->disconnect();
		asserter.registerSteppable(clientOffDevices2.emplace_back(client));
	}

	SLOGD << "Step 2: Send message";
	bool isRequestAccepted = false;
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&isRequestAccepted](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 200);
			    isRequestAccepted = true;
		    }
	    },
	    nullptr,
	};

	const string body{"C'est pas faux \r\n\r\n"};
	stringstream request{};
	request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1\r\n"
	        << "From: <sip:kijou@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	        << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	        << "CSeq: 20 MESSAGE\r\n"
	        << "Call-ID: Tvw6USHXYv\r\n"
	        << "Max-Forwards: 70\r\n"
	        << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Supported: replaces, outbound, gruu\r\n"
	        << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	        << "Content-Type: text/plain\r\n"
	        << "Content-Length: " << body.size() << "\r\n\r\n";
	belleSipUtils.sendRawRequest(request.str(), body);

	CoreAssert asserterBis{server, belleSipUtils};
	asserterBis.registerSteppables(clientOnDevices);
	asserterBis.wait([&isRequestAccepted]() { return LOOP_ASSERTION(isRequestAccepted); }).assert_passed();

	asserter
	    .wait([&clientOnDevices] {
		    return LOOP_ASSERTION(
		        all_of(clientOnDevices.begin(), clientOnDevices.end(), [](const auto& clientOnDevice) {
			        return clientOnDevice->getAccount()->getState() == RegistrationState::Ok &&
			               clientOnDevice->getCore()->getUnreadChatMessageCount() == 1;
		        }));
	    })
	    .assert_passed();

	SLOGD << "Step 3: Assert that db fork is still present because some devices are offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 1);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 1);

	SLOGD << "Step 4: Check that request in DB is the same that request sent";
	const auto allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	if (allMessages.size() == 1) {
		const auto requestInDb =
		    ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(allMessages.cbegin()->uuid).request;
		// We only compare body because headers can be modified a bit by the proxy.
		if (requestInDb.find(body) == string::npos) BC_FAIL("Body not found");
	} else BC_FAIL("No message in DB, or too much");

	SLOGD << "Step 5: REGISTER first group of devices and receive message";
	for_each(clientOffDevices1.begin(), clientOffDevices1.end(), [](const auto& core) { core->reconnect(); });
	asserter
	    .wait([&clientOffDevices1] {
		    return LOOP_ASSERTION(
		        all_of(clientOffDevices1.begin(), clientOffDevices1.end(), [](const auto& clientOffDevice) {
			        return clientOffDevice->getAccount()->getState() == RegistrationState::Ok &&
			               clientOffDevice->getCore()->getUnreadChatMessageCount() == 1;
		        }));
	    })
	    .assert_passed();

	SLOGD << "Step 6: Unregister initial group of device, for a future register";
	for_each(clientOnDevices.begin(), clientOnDevices.end(), [](const auto& core) { core->disconnect(); });

	SLOGD << "Step 7: Assert that db fork is still present because some devices are offline, message fork is destroyed "
	         "because message is saved";
	asserter
	    .iterateUpTo(
	        128,
	        [&moduleRouter] {
		        return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 2);
	        },
	        3s)
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 2);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 2);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);

	SLOGD << "Step 8: Re-REGISTER initial group, ForkMessage is retrieve from DB, but no message is sent";
	for_each(clientOnDevices.begin(), clientOnDevices.end(), [](const auto& core) { core->reconnect(); });
	for_each(clientOnDevices.begin(), clientOnDevices.end(),
	         [](const auto& core) { core->getCore()->getChatRooms().begin()->get()->markAsRead(); });

	SLOGD << "Step 8b: REGISTER second group of devices and receive message";
	for_each(clientOffDevices2.begin(), clientOffDevices2.end(), [](const auto& core) { core->reconnect(); });
	asserter
	    .wait([&clientOnDevices, &clientOffDevices2] {
		    return LOOP_ASSERTION(
		        all_of(clientOffDevices2.begin(), clientOffDevices2.end(),
		               [](const auto& clientOffDevice) {
			               return clientOffDevice->getAccount()->getState() == RegistrationState::Ok &&
			                      clientOffDevice->getCore()->getUnreadChatMessageCount() == 1;
		               }) &&
		        all_of(clientOnDevices.begin(), clientOnDevices.end(), [](const auto& clientOnDevice) {
			        return clientOnDevice->getAccount()->getState() == RegistrationState::Ok &&
			               clientOnDevice->getCore()->getUnreadChatMessageCount() == 0;
		        }));
	    })
	    .assert_passed();

	SLOGD << "Step 9: Assert Fork is destroyed after being delivered (from memory AND database)";
	asserter
	    .wait([&moduleRouter] {
		    const auto& allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read() == 1 &&
		                          allMessages.empty());
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_GREATER(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 3, int, "%i");
	BC_ASSERT_GREATER(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 3, int, "%i");
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(),
	                    moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read());
}

void testDBAccessOptimization() {
	SLOGD << "Step 1: Setup";
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto clientOnDevice = builder.build("sip:provencal_le_gaulois@sip.test.org;device=on");
	auto clientOffDevice = builder.build("sip:provencal_le_gaulois@sip.test.org;device=off");
	clientOffDevice.disconnect();

	bool isRequestAccepted = false;
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&isRequestAccepted](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 200);
			    isRequestAccepted = true;
		    }
	    },
	    nullptr,
	};

	SLOGD << "Step 2: Send message";
	string body(10, 'a');
	body.insert(0, "C'est pas faux \r\n\r\n");
	stringstream request{};
	request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1\r\n"
	        << "From: <sip:kijou@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	        << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	        << "CSeq: 20 MESSAGE\r\n"
	        << "Call-ID: Tvw6USHXYv\r\n"
	        << "Max-Forwards: 70\r\n"
	        << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Supported: replaces, outbound, gruu\r\n"
	        << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	        << "Content-Type: text/plain\r\n"
	        << "Content-Length: " << body.size() << "\r\n\r\n";
	belleSipUtils.sendRawRequest(request.str(), body);

	CoreAssert asserter{server, belleSipUtils, clientOnDevice, clientOffDevice};
	asserter.wait([&isRequestAccepted]() { return LOOP_ASSERTION(isRequestAccepted); }).assert_passed();

	asserter
	    .wait([&clientOnDevice] {
		    return LOOP_ASSERTION(clientOnDevice.getAccount()->getState() == RegistrationState::Ok &&
		                          clientOnDevice.getCore()->getUnreadChatMessageCount() == 1);
	    })
	    .assert_passed();

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 1);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 1);

	SLOGD << "Step 4: Force a second register, fork is re-created from DB";
	clientOnDevice.disconnect();
	clientOnDevice.getCore()->iterate();
	clientOnDevice.reconnect();
	asserter
	    .wait([&clientOnDevice] {
		    return LOOP_ASSERTION(clientOnDevice.getAccount()->getState() == RegistrationState::Ok);
	    })
	    .assert_passed();
	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 2);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 2);

	SLOGD << "Step 5: Force a third register, fork is NOT re-created from DB";
	clientOnDevice.disconnect();
	clientOnDevice.getCore()->iterate();
	clientOnDevice.reconnect();
	asserter
	    .wait([&clientOnDevice] {
		    return LOOP_ASSERTION(clientOnDevice.getAccount()->getState() == RegistrationState::Ok);
	    })
	    .assert_passed();
	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 2);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 2);

	SLOGD << "Step 6: Register second devices, check fork destruction";
	clientOffDevice.reconnect();
	asserter
	    .wait([&clientOffDevice] {
		    return LOOP_ASSERTION(clientOffDevice.getAccount()->getState() == RegistrationState::Ok &&
		                          clientOffDevice.getCore()->getUnreadChatMessageCount() == 1);
	    })
	    .assert_passed();
	asserter
	    .wait([&moduleRouter] {
		    const auto& allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read() == 1 &&
		                          allMessages.empty());
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 3);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 3);
}

/**
 * This test is a performance test, and too much system dependant.
 */
#ifdef false
/**
 * Same test as globalTest, but this time we send a lot of large message while receiver is not reachable.
 * This test try to saturate sofia-sip queue when receiver register again. If all messages are received test is passed.
 */
static void globalTestMultipleMessages() {
	// This test log too much, modify this value to "BCTBX_LOG_DEBUG" if you need logs
	bctbx_set_log_level(nullptr, BCTBX_LOG_FATAL);
	Server server{configuration};
	server.start();

	auto receiverClient = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server.getAgent());
	receiverClient->getCore()->setNetworkReachable(false);

	unsigned nbAcceptedMessages = 0;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&nbAcceptedMessages](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            ++nbAcceptedMessages;
		                            }
	                            },
	                            nullptr};

	unsigned int i = 0;
	std::string rawBody(10000, 'a');
	rawBody.append("\r\n\r\n");
	for (; i < 1000; ++i) {
		ostringstream rawHeaders;
		rawHeaders << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
		              "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
		              "From: <sip:kijou@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		              "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
		              "CSeq: 20 MESSAGE\r\n"
		              "Call-ID: Tvw6USHXYv"
		           << i
		           << "\r\n"
		              "Max-Forwards: 70\r\n"
		              "Route: <sip:127.0.0.1:5960;transport=tcp;lr>\r\n"
		              "Supported: replaces, outbound, gruu\r\n"
		              "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
		              "Content-Type: text/plain\r\n\r\n";
		bellesipUtils.sendRawRequest(rawHeaders.str(), rawBody);
	}

	auto beforePlus10 = system_clock::now() + 10s;
	while (nbAcceptedMessages != i && beforePlus10 >= system_clock::now()) {
		bellesipUtils.stackSleep(10);
		server.getAgent()->getRoot()->step(10ms);
	}
	BC_ASSERT_EQUAL(nbAcceptedMessages, i, int, "%i");

	/*
	 * Assert that db fork is still present because device is offline, message fork is destroyed because message is
	 * saved
	 */
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	if (!CoreAssert(receiverClient, server.getAgent()).wait([&moduleRouter, i] {
		    return moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == i;
	    })) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), i, int, "%i");
	}
	BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), i, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), i, int, "%i");

	// Client REGISTER and receive message
	receiverClient->getCore()->setNetworkReachable(true);
	if (!CoreAssert(receiverClient, server.getAgent()).waitUntil(20s, [receiverClient, i] {
		    return receiverClient->getAccount()->getState() == RegistrationState::Ok &&
		           (unsigned int)receiverClient->getCore()->getUnreadChatMessageCount() == i;
	    })) {
		BC_ASSERT_EQUAL(receiverClient->getCore()->getUnreadChatMessageCount(), i, int, "%i");
	}

	// Assert Fork is destroyed after being delivered
	if (!CoreAssert(receiverClient, server.getAgent()).waitUntil(10s, [&moduleRouter, i] {
		    return moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read() == i;
	    })) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), i, int, "%i");
	}
	if (moduleRouter) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), i, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 2 * i, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 2 * i, int, "%i");
	}

	// MANDATORY, see first line of this test
	bctbx_set_log_level(nullptr, BCTBX_LOG_DEBUG);
}
#endif

/*
 * We send a message to a client with one idle device, to force the message saving in DB.
 * To simulate a problem with the message in DB we delete everything in DB.
 * Then we put the client back online, and we check that nothing is delivered and that no crash happened.
 * All along we check fork stats and client state.
 */
void globalTestDatabaseDeleted() {
	SLOGD << "Step 1: Setup";
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto receiverClient = builder.build("sip:provencal_le_gaulois@sip.test.org");
	receiverClient.disconnect();

	bool isRequestAccepted = false;
	BellesipUtils belleSipUtils{
	    "0.0.0.0",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "TCP",
	    [&isRequestAccepted](int status) {
		    if (status != 100) {
			    BC_ASSERT_CPP_EQUAL(status, 202);
			    isRequestAccepted = true;
		    }
	    },
	    nullptr,
	};

	SLOGD << "Step 2: Send message";
	const string body{"C'est pas faux \r\n\r\n"};
	stringstream request{};
	request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	        << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1\r\n"
	        << "From: <sip:kijou@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	        << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	        << "CSeq: 20 MESSAGE\r\n"
	        << "Call-ID: Tvw6USHXYv\r\n"
	        << "Max-Forwards: 70\r\n"
	        << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
	        << "Supported: replaces, outbound, gruu\r\n"
	        << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	        << "Content-Type: text/plain\r\n"
	        << "Content-Length: " << body.size() << "\r\n\r\n";
	belleSipUtils.sendRawRequest(request.str(), body);

	CoreAssert asserter{server, belleSipUtils, receiverClient};
	asserter.wait([&isRequestAccepted]() { return LOOP_ASSERTION(isRequestAccepted); }).assert_passed();

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);

	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == 1);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 1);

	SLOGD << "Step 4: Clear database to simulate DB errors on Client REGISTER.";
	ForkMessageContextSociRepository::getInstance()->deleteAll();

	SLOGD << "Step 4b: Client REGISTER, no message received.";
	receiverClient.reconnect();
	asserter
	    .wait([&receiverClient] {
		    return LOOP_ASSERTION(receiverClient.getAccount()->getState() == RegistrationState::Ok &&
		                          receiverClient.getCore()->getUnreadChatMessageCount() == 0);
	    })
	    .assert_passed();

	SLOGD << "Step 5: Assert Fork is destroyed even if the ForkMessage can't be rebuilt because of an empty database.";
	asserter
	    .wait([&moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read() == 1);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 1);
}

/**
 * We send multiples message to a client with one idle device, to force the messages saving in DB.
 * Then we put the client back online and see if the messages are correctly delivered AND IN ORDER.
 * All along we check fork stats and client state.
 */
void globalOrderTest() {
	SLOGD << "Step 1: Setup";
	Server server{configuration};
	forceSociRepositoryInstantiation();
	server.start();

	const auto router = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	router->getForkManager()->setMaxPriorityHandled(MsgSipPriority::Emergency);

	ClientBuilder builder{*server.getAgent()};
	auto receiverClient = builder.build("sip:provencal_le_gaulois@sip.test.org");
	receiverClient.disconnect();

	uint isRequestAccepted = 0;
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

	SLOGD << "Step 2: Send messages, in priority disorder.";
	uint messageSent = 0;
	uint reelOrderIndex = 0;
	const auto& priorities = vector<string>{"non-urgent", "emergency", "normal", "urgent", "normal", "emergency"};
	const auto& reelOrders = vector<vector<uint>>{
	    {16, 17, 18}, {1, 2, 3}, {10, 11, 12}, {7, 8, 9}, {13, 14, 15}, {4, 5, 6},
	};

	const auto request = [&server](const uint callId = 0, const string& priority = "normal"s,
	                               const size_t contentLength = 0) {
		stringstream request{};
		request << "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
		        << "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1\r\n"
		        << "From: <sip:kijou@sip.test.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
		        << "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
		        << "CSeq: 20 MESSAGE\r\n"
		        << "Priority: " << priority << "\r\n"
		        << "Call-ID: Tvw6USHXYv-" << callId << "\r\n"
		        << "Max-Forwards: 70\r\n"
		        << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
		        << "Supported: replaces, outbound, gruu\r\n"
		        << "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
		        << "Content-Type: text/plain\r\n"
		        << "Content-Length: " << contentLength << "\r\n\r\n";
		return request.str();
	};

	CoreAssert asserter{server, belleSipUtils, receiverClient};
	for (const auto& priority : priorities) {
		for (const auto orderValue : reelOrders.at(reelOrderIndex)) {
			const string body{"C'est pas faux "s + to_string(orderValue) + "\r\n\r\n"};
			belleSipUtils.sendRawRequest(request(orderValue, priority, body.size()), body);

			messageSent++;
			asserter
			    .wait([&isRequestAccepted, &messageSent]() { return LOOP_ASSERTION(isRequestAccepted == messageSent); })
			    .assert_passed();
		}
		reelOrderIndex++;
	}

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);

	asserter
	    .wait([&moduleRouter, &messageSent] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read() == messageSent);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), messageSent);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read(), 0);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), messageSent);

	SLOGD << "Step 4: Client REGISTER, then receive message";
	receiverClient.reconnect();
	BC_ASSERT_TRUE(asserter.wait([&receiverClient, &messageSent] {
		return receiverClient.getAccount()->getState() == RegistrationState::Ok &&
		       (uint)receiverClient.getCore()->getUnreadChatMessageCount() == messageSent;
	}));

	SLOGD << "Step 5: Check messages order";
	auto messages = receiverClient.getChatMessages();
	uint order = 1;
	for (const auto& message : messages) {
		const auto actual = message->getUtf8Text();
		BC_ASSERT_CPP_EQUAL(actual, string{"C'est pas faux "s + to_string(order) + "\r\n\r\n"});
		order++;
	}
	BC_ASSERT_CPP_EQUAL(order - 1, messageSent);

	SLOGD << "Step 6: Check fork stats";
	asserter
	    .wait([&moduleRouter, &messageSent] {
		    return LOOP_ASSERTION(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->finish->read() ==
		                          messageSent);
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageProxyForks->start->read(), messageSent);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->start->read(), 2 * messageSent);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mForkStats->mCountMessageForks->finish->read(), 2 * messageSent);
}

TestSuite _{
    "ForkContext::mysql",
    {
        CLASSY_TEST(forkMessageContextSociRepositoryMysql),
        CLASSY_TEST(forkMessageContextWithBranchesSociRepositoryMysql),
        CLASSY_TEST(forkMessageContextSociRepositoryFullLoadMysql),
        CLASSY_TEST(globalTest),
        CLASSY_TEST(globalTestMultipleDevices),
        CLASSY_TEST(testDBAccessOptimization),
        CLASSY_TEST(globalTestDatabaseDeleted),
        CLASSY_TEST(globalOrderTest),
    },
    Hooks()
        .beforeSuite([] {
	        mysqlServer.emplace();
	        ForkMessageContextSociRepository::prepareConfiguration("mysql", mysqlServer->connectionString(), 10);
	        return 0;
        })
        .afterEach([] { ForkMessageContextSociRepository::getInstance()->deleteAll(); })
        .afterSuite([] {
	        mysqlServer.reset();
	        return 0;
        }),
};

} // namespace
} // namespace flexisip::tester