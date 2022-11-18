/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "fork-context/fork-message-context-db-proxy.hh"
#include "fork-context/fork-message-context-soci-repository.hh"
#include "utils/asserts.hh"
#include "utils/bellesip-utils.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace linphone;
using namespace sofiasip;

namespace flexisip {
namespace tester {

using days = duration<int, ratio_multiply<ratio<24>, hours::period>>;

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

static void forkMessageContextSociRepositoryMysqlUnitTests() {
	auto server = make_unique<Server>("/config/flexisip_fork_context_db.conf");
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));

	// Save and find test
	auto nowPlusDays = system_clock::now() + days{7};
	std::time_t t = system_clock::to_time_t(nowPlusDays);
	ForkMessageContextDb fakeDbObject{1, 3, true, false, *gmtime(&t), rawRequest, MsgSipPriority::NonUrgent};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
	auto expectedFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, fakeDbObject);
	auto insertedUuid =
	    ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, dbFork);
	actualFork->assertEqual(expectedFork);

	// Update and find test
	nowPlusDays = system_clock::now() + days{10};
	t = system_clock::to_time_t(nowPlusDays);
	fakeDbObject = ForkMessageContextDb{2, 10, false, true, *gmtime(&t), rawRequest, MsgSipPriority::Urgent};
	fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"}; // We keep the same keys because they are not updated
	expectedFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, fakeDbObject);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork->getDbObject(),
	                                                                          insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, dbFork);
	actualFork->assertEqual(expectedFork);
}

static void forkMessageContextWithBranchesSociRepositoryMysqlUnitTests() {
	auto server = make_unique<Server>("/config/flexisip_fork_context_db.conf");
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));

	// Save and find with branch info test
	auto nowPlusDays = system_clock::now() + days{400};
	auto t = system_clock::to_time_t(nowPlusDays);
	auto fakeDbObject = ForkMessageContextDb{1.52, 5, false, true, *gmtime(&t), rawRequest, MsgSipPriority::Normal};
	fakeDbObject.dbKeys = vector<string>{"key1"};
	BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
	BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
	BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	auto expectedFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, fakeDbObject);

	auto insertedUuid =
	    ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	auto actualFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, dbFork);
	actualFork->assertEqual(expectedFork);

	// Update and find with branch info test
	nowPlusDays = system_clock::now() + days{10};
	t = system_clock::to_time_t(nowPlusDays);
	fakeDbObject = ForkMessageContextDb{10, 1000, true, false, *gmtime(&t), rawRequest, MsgSipPriority::Emergency};
	fakeDbObject.dbKeys = vector<string>{"key1"}; // We keep the same keys because they are not updated
	branchInfoDb = BranchInfoDb{"contactUid", 3.0, rawRequest, rawResponse, false};
	branchInfoDb2 = BranchInfoDb{"contactUid2", 3.0, rawRequest, rawResponse, true};
	branchInfoDb3 = BranchInfoDb{"contactUid3", 3.42, rawRequest, rawResponse, false};
	fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
	expectedFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, fakeDbObject);
	ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(expectedFork->getDbObject(),
	                                                                          insertedUuid);
	dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(insertedUuid);
	actualFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, dbFork);
	actualFork->assertEqual(expectedFork);
}

static void forkMessageContextSociRepositoryFullLoadMysqlUnitTests() {
	auto server = make_unique<Server>("/config/flexisip_fork_context_db.conf");
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));

	map<string, shared_ptr<ForkMessageContext>> expectedForks{};
	for (int i = 0; i < 10; i++) {
		auto nowPlusDays = system_clock::now() + days{400};
		auto t = system_clock::to_time_t(nowPlusDays);
		auto fakeDbObject =
		    ForkMessageContextDb{1.52, 5, false, true, *gmtime(&t), rawRequest, MsgSipPriority::NonUrgent};
		fakeDbObject.dbKeys = vector<string>{"key"};
		BranchInfoDb branchInfoDb{"contactUid", 4.0, rawRequest, rawResponse, true};
		BranchInfoDb branchInfoDb2{"contactUid2", 1.0, rawRequest, rawResponse, false};
		BranchInfoDb branchInfoDb3{"contactUid3", 2.42, rawRequest, rawResponse, true};
		fakeDbObject.dbBranches = vector<BranchInfoDb>{branchInfoDb, branchInfoDb2, branchInfoDb3};
		auto expectedFork = ForkMessageContext::make(moduleRouter, shared_ptr<ForkContextListener>{}, fakeDbObject);
		auto insertedUuid =
		    ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(expectedFork->getDbObject());
		expectedForks.insert(make_pair(insertedUuid, expectedFork));
	}

	auto dbForks = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	map<string, shared_ptr<ForkMessageContextDbProxy>> actualForks{};

	for (auto dbFork : dbForks) {
		auto actualFork = ForkMessageContextDbProxy::make(moduleRouter, dbFork);
		actualForks.insert(make_pair(dbFork.uuid, actualFork));
		BC_ASSERT_TRUE(!dbFork.dbKeys.empty());
	}

	if (actualForks.size() != expectedForks.size()) {
		BC_FAIL("[" << expectedForks.size() << "] expected forks but [" << actualForks.size() << "]found");
	}
	for (const auto& actualFork : actualForks) {
		auto it = expectedForks.find(actualFork.first);
		if (it == expectedForks.end()) {
			BC_FAIL("Forks with UUID " << actualFork.first << "not expected");
		}
	}
}

/**
 * We send a message to a client with one idle device, to force the message saving in DB.
 * At this point we assert that the message saved in DB is the same as the one sent.
 * Then we put the client back online and see if the message is correctly delivered.
 * All along we check fork stats and client state.
 */
static void globalTest() {
	SLOGD << "Step 1: Setup";
	auto server = make_shared<Server>("/config/flexisip_fork_context_db.conf");
	server->start();

	auto receiverClient = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
	receiverClient->getCore()->setNetworkReachable(false);

	bool isRequestAccepted = false;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&isRequestAccepted](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            isRequestAccepted = true;
		                            }
	                            },
	                            nullptr};

	SLOGD << "Step 2: Send message";
	std::string rawBody(100000, 'a');
	rawBody.insert(0, "C'est pas faux ");
	rawBody.append("\r\n\r\n");
	bellesipUtils.sendRawRequest("MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	                             "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
	                             "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	                             "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	                             "CSeq: 20 MESSAGE\r\n"
	                             "Call-ID: Tvw6USHXYv\r\n"
	                             "Max-Forwards: 70\r\n"
	                             "Route: <sip:127.0.0.1:5960;transport=tcp;lr>\r\n"
	                             "Supported: replaces, outbound, gruu\r\n"
	                             "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	                             "Content-Type: text/plain\r\n",
	                             rawBody);
	auto beforePlus2 = system_clock::now() + 2s;
	while (!isRequestAccepted && beforePlus2 >= system_clock::now()) {
		server->getAgent()->getRoot()->step(20ms);
		bellesipUtils.stackSleep(20);
	}

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 1, int, "%i");

	SLOGD << "Step 4: Check that request in DB is the same that request sent";
	auto allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	if (allMessages.size() == 1) {
		auto requestInDb =
		    ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(allMessages.cbegin()->uuid).request;
		// We only compare body because headers can be modified a bit by the proxy
		if (requestInDb.find(rawBody) == string::npos) BC_FAIL("Body not found");
	} else BC_FAIL("No message in DB, or too much");

	SLOGD << "Step 5: Client REGISTER, then receive message";
	receiverClient->getCore()->setNetworkReachable(true);
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([receiverClient] {
		return receiverClient->getAccount()->getState() == RegistrationState::Ok &&
		       receiverClient->getCore()->getUnreadChatMessageCount() == 1;
	}));

	SLOGD << "Step 6: Client REGISTER, then receive message";
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageProxyForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 2, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 2, int, "%i");
}

static void globalTestMultipleDevices() {
	SLOGD << "Step 1: Setup";
	auto server = make_shared<Server>("/config/flexisip_fork_context_db.conf");
	server->start();

	vector<shared_ptr<CoreClient>> clientOnDevices{};
	for (int i = 0; i < 3; ++i) {
		clientOnDevices.emplace_back(make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server));
	}

	vector<shared_ptr<CoreClient>> clientOffDevices1{};
	for (int i = 0; i < 3; ++i) {
		auto client = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
		client->getCore()->setNetworkReachable(false);
		clientOffDevices1.emplace_back(client);
	}

	vector<shared_ptr<CoreClient>> clientOffDevices2{};
	for (int i = 0; i < 3; ++i) {
		auto client = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
		client->getCore()->setNetworkReachable(false);
		clientOffDevices2.emplace_back(client);
	}

	SLOGD << "Step 2: Send message";
	bool isRequestAccepted = false;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&isRequestAccepted](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            isRequestAccepted = true;
		                            }
	                            },
	                            nullptr};

	std::string rawBody(10, 'a');
	rawBody.insert(0, "C'est pas faux ");
	rawBody.append("\r\n\r\n");
	bellesipUtils.sendRawRequest("MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	                             "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
	                             "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	                             "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	                             "CSeq: 20 MESSAGE\r\n"
	                             "Call-ID: Tvw6USHXYv\r\n"
	                             "Max-Forwards: 70\r\n"
	                             "Route: <sip:127.0.0.1:5960;transport=tcp;lr>\r\n"
	                             "Supported: replaces, outbound, gruu\r\n"
	                             "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	                             "Content-Type: text/plain\r\n",
	                             rawBody);
	auto beforePlus2 = system_clock::now() + 2s;
	while (!isRequestAccepted && beforePlus2 >= system_clock::now()) {
		server->getAgent()->getRoot()->step(20ms);
		bellesipUtils.stackSleep(20);
	}

	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevices, clientOffDevices1, clientOffDevices2).wait([&clientOnDevices] {
		return all_of(clientOnDevices.begin(), clientOnDevices.end(), [](const auto& clientOnDevice) {
			return clientOnDevice->getAccount()->getState() == RegistrationState::Ok &&
			       clientOnDevice->getCore()->getUnreadChatMessageCount() == 1;
		});
	}));

	SLOGD << "Step 3: Assert that db fork is still present because some devices are offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(
	    CoreAssert(server, clientOnDevices, clientOffDevices1, clientOffDevices2).wait([agent = server->getAgent()] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    return moduleRouter->mStats.mCountMessageForks->finish->read() == 1;
	    }));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 1, int, "%i");

	SLOGD << "Step 4: Check that request in DB is the same that request sent";
	auto allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
	if (allMessages.size() == 1) {
		auto requestInDb =
		    ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(allMessages.cbegin()->uuid).request;
		// We only compare body because headers can be modified a bit by the proxy
		if (requestInDb.find(rawBody) == string::npos) BC_FAIL("Body not found");
	} else BC_FAIL("No message in DB, or too much");

	SLOGD << "Step 5: REGISTER first group of devices and receive message";
	for_each(clientOffDevices1.begin(), clientOffDevices1.end(),
	         [](const auto& core) { core->getCore()->setNetworkReachable(true); });
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevices, clientOffDevices1, clientOffDevices2).wait([&clientOffDevices1] {
		return all_of(clientOffDevices1.begin(), clientOffDevices1.end(), [](const auto& clientOffDevice) {
			return clientOffDevice->getAccount()->getState() == RegistrationState::Ok &&
			       clientOffDevice->getCore()->getUnreadChatMessageCount() == 1;
		});
	}));

	SLOGD << "Step 6: Unregister initial group of device, for a future register";
	for_each(clientOnDevices.begin(), clientOnDevices.end(),
	         [](const auto& core) { core->getCore()->setNetworkReachable(false); });

	SLOGD << "Step 7: Assert that db fork is still present because some devices are offline, message fork is destroyed "
	         "because message is saved";
	BC_ASSERT_TRUE(
	    CoreAssert(server, clientOnDevices, clientOffDevices1, clientOffDevices2).wait([agent = server->getAgent()] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    return moduleRouter->mStats.mCountMessageForks->finish->read() == 2;
	    }));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 2, int, "%i");

	SLOGD << "Step 8: Re-REGISTER initial group, ForkMessage is retrieve from DB, but no message is sent";
	for_each(clientOnDevices.begin(), clientOnDevices.end(),
	         [](const auto& core) { core->getCore()->setNetworkReachable(true); });
	for_each(clientOnDevices.begin(), clientOnDevices.end(),
	         [](const auto& core) { core->getCore()->getChatRooms().begin()->get()->markAsRead(); });
	SLOGD << "Step 8b: REGISTER second group of devices and receive message";
	for_each(clientOffDevices2.begin(), clientOffDevices2.end(),
	         [](const auto& core) { core->getCore()->setNetworkReachable(true); });
	BC_ASSERT_TRUE(
	    CoreAssert(server, clientOnDevices, clientOffDevices1, clientOffDevices2)
	        .wait([&clientOnDevices, &clientOffDevices2] {
		        return all_of(clientOffDevices2.begin(), clientOffDevices2.end(),
		                      [](const auto& clientOffDevice) {
			                      return clientOffDevice->getAccount()->getState() == RegistrationState::Ok &&
			                             clientOffDevice->getCore()->getUnreadChatMessageCount() == 1;
		                      }) &&
		               all_of(clientOnDevices.begin(), clientOnDevices.end(), [](const auto& clientOnDevice) {
			               return clientOnDevice->getAccount()->getState() == RegistrationState::Ok &&
			                      clientOnDevice->getCore()->getUnreadChatMessageCount() == 0;
		               });
	        }));

	SLOGD << "Step 9: Assert Fork is destroyed after being delivered (from memory AND database)";
	BC_ASSERT_TRUE(
	    CoreAssert(server, clientOnDevices, clientOffDevices1, clientOffDevices2).wait([agent = server->getAgent()] {
		    const auto& allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    return moduleRouter->mStats.mCountMessageProxyForks->finish->read() == 1 && allMessages.empty();
	    }));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_GREATER(moduleRouter->mStats.mCountMessageForks->start->read(), 3, int, "%i");
	BC_ASSERT_GREATER(moduleRouter->mStats.mCountMessageForks->finish->read(), 3, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(),
	                moduleRouter->mStats.mCountMessageForks->finish->read(), int, "%i");
}

static void testDBAccessOptimization() {
	SLOGD << "Step 1: Setup";
	auto server = make_shared<Server>("/config/flexisip_fork_context_db.conf");
	server->start();

	shared_ptr<CoreClient> clientOnDevice = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);

	shared_ptr<CoreClient> clientOffDevice = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
	clientOffDevice->getCore()->setNetworkReachable(false);

	bool isRequestAccepted = false;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&isRequestAccepted](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            isRequestAccepted = true;
		                            }
	                            },
	                            nullptr};

	SLOGD << "Step 2: Send message";
	std::string rawBody(10, 'a');
	rawBody.insert(0, "C'est pas faux ");
	rawBody.append("\r\n\r\n");
	bellesipUtils.sendRawRequest("MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	                             "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
	                             "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	                             "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	                             "CSeq: 20 MESSAGE\r\n"
	                             "Call-ID: Tvw6USHXYv\r\n"
	                             "Max-Forwards: 70\r\n"
	                             "Route: <sip:127.0.0.1:5960;transport=tcp;lr>\r\n"
	                             "Supported: replaces, outbound, gruu\r\n"
	                             "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	                             "Content-Type: text/plain\r\n",
	                             rawBody);
	auto beforePlus2 = system_clock::now() + 2s;
	while (!isRequestAccepted && beforePlus2 >= system_clock::now()) {
		server->getAgent()->getRoot()->step(20ms);
		bellesipUtils.stackSleep(20);
	}

	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([&clientOnDevice] {
		return clientOnDevice->getAccount()->getState() == RegistrationState::Ok &&
		       clientOnDevice->getCore()->getUnreadChatMessageCount() == 1;
	}));

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 1, int, "%i");

	SLOGD << "Step 4: Force a second register, fork is re-created from DB";
	clientOnDevice->getCore()->setNetworkReachable(false);
	clientOnDevice->getCore()->iterate();
	clientOnDevice->getCore()->setNetworkReachable(true);
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([&clientOnDevice] {
		return clientOnDevice->getAccount()->getState() == RegistrationState::Ok;
	}));
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->finish->read() == 2;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 2, int, "%i");

	SLOGD << "Step 5: Force a third register, fork is NOT re-created from DB";
	clientOnDevice->getCore()->setNetworkReachable(false);
	clientOnDevice->getCore()->iterate();
	clientOnDevice->getCore()->setNetworkReachable(true);
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([&clientOnDevice] {
		return clientOnDevice->getAccount()->getState() == RegistrationState::Ok;
	}));
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->finish->read() == 2;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 2, int, "%i");

	SLOGD << "Step 6: Register second devices, check fork destruction";
	clientOffDevice->getCore()->setNetworkReachable(true);
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([&clientOffDevice] {
		return clientOffDevice->getAccount()->getState() == RegistrationState::Ok &&
		       clientOffDevice->getCore()->getUnreadChatMessageCount() == 1;
	}));
	BC_ASSERT_TRUE(CoreAssert(server, clientOnDevice, clientOffDevice).wait([agent = server->getAgent()] {
		const auto& allMessages = ForkMessageContextSociRepository::getInstance()->findAllForkMessage();
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageProxyForks->finish->read() == 1 && allMessages.empty();
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 3, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 3, int, "%i");
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
	auto server = make_shared<Server>("/config/flexisip_fork_context_db.conf");
	server->start();

	auto receiverClient = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
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
		              "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
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
		server->getAgent()->getRoot()->step(10ms);
	}
	BC_ASSERT_EQUAL(nbAcceptedMessages, i, int, "%i");

	/*
	 * Assert that db fork is still present because device is offline, message fork is destroyed because message is
	 * saved
	 */
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	if (!CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([&moduleRouter, i] {
		    return moduleRouter->mStats.mCountMessageForks->finish->read() == i;
	    })) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), i, int, "%i");
	}
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), i, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), i, int, "%i");

	// Client REGISTER and receive message
	receiverClient->getCore()->setNetworkReachable(true);
	if (!CoreAssert({receiverClient->getCore()}, server->getAgent()).waitUntil(20s, [receiverClient, i] {
		    return receiverClient->getAccount()->getState() == RegistrationState::Ok &&
		           (unsigned int)receiverClient->getCore()->getUnreadChatMessageCount() == i;
	    })) {
		BC_ASSERT_EQUAL(receiverClient->getCore()->getUnreadChatMessageCount(), i, int, "%i");
	}

	// Assert Fork is destroyed after being delivered
	if (!CoreAssert({receiverClient->getCore()}, server->getAgent()).waitUntil(10s, [&moduleRouter, i] {
		    return moduleRouter->mStats.mCountMessageProxyForks->finish->read() == i;
	    })) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), i, int, "%i");
	}
	if (moduleRouter) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), i, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 2 * i, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 2 * i, int, "%i");
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
static void globalTestDatabaseDeleted() {
	SLOGD << "Step 1: Setup";
	auto server = make_shared<Server>("/config/flexisip_fork_context_db.conf");
	server->start();

	auto receiverClient = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
	receiverClient->getCore()->setNetworkReachable(false);

	bool isRequestAccepted = false;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&isRequestAccepted](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            isRequestAccepted = true;
		                            }
	                            },
	                            nullptr};

	SLOGD << "Step 2: Send message";
	bellesipUtils.sendRawRequest("MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	                             "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
	                             "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	                             "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	                             "CSeq: 20 MESSAGE\r\n"
	                             "Call-ID: Tvw6USHXYv\r\n"
	                             "Max-Forwards: 70\r\n"
	                             "Route: <sip:127.0.0.1:5960;transport=tcp;lr>\r\n"
	                             "Supported: replaces, outbound, gruu\r\n"
	                             "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	                             "Content-Type: text/plain\r\n"
	                             "Content-Length: 14\r\n",
	                             "C'est pas faux");
	auto beforePlus2 = system_clock::now() + 2s;
	while (!isRequestAccepted && beforePlus2 >= system_clock::now()) {
		server->getAgent()->getRoot()->step(20ms);
		bellesipUtils.stackSleep(20);
	}

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 1, int, "%i");

	SLOGD << "Step 4: Clear database to simulate DB errors on Client REGISTER.";
	ForkMessageContextSociRepository::getInstance()->deleteAll();

	SLOGD << "Step 4b: Client REGISTER, no message received.";
	receiverClient->getCore()->setNetworkReachable(true);
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([receiverClient] {
		return receiverClient->getAccount()->getState() == RegistrationState::Ok &&
		       receiverClient->getCore()->getUnreadChatMessageCount() == 0;
	}));

	SLOGD << "Step 5: Assert Fork is destroyed even if the ForkMessage can't be rebuilt because of an empty database.";
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountMessageProxyForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 1, int, "%i");
}

string getMessagesHeaders(uint callIdPostfix = 0, string msgPriority = "normal"s) {
	return "MESSAGE sip:provencal_le_gaulois@sip.test.org SIP/2.0\r\n"
	       "Via: SIP/2.0/TCP 127.0.0.1:6066;branch=z9hG4bK.PAWTmCZv1;rport=49828\r\n"
	       "From: <sip:kijou@sip.linphone.org;gr=8aabdb1c>;tag=l3qXxwsO~\r\n"
	       "To: <sip:provencal_le_gaulois@sip.test.org>\r\n"
	       "CSeq: 20 MESSAGE\r\n"
	       "Priority: " +
	       msgPriority +
	       "\r\n"
	       "Call-ID: Tvw6USHXYv" +
	       to_string(callIdPostfix) +
	       "\r\n"
	       "Max-Forwards: 70\r\n"
	       "Route: <sip:127.0.0.1:5960;transport=tcp;lr>\r\n"
	       "Supported: replaces, outbound, gruu\r\n"
	       "Date: Fri, 01 Apr 2022 11:18:26 GMT\r\n"
	       "Content-Type: text/plain\r\n";
}
/**
 * We send multiples message to a client with one idle device, to force the messages saving in DB.
 * Then we put the client back online and see if the messages are correctly delivered AND IN ORDER.
 * All along we check fork stats and client state.
 */
static void globalOrderTest() {
	SLOGD << "Step 1: Setup";
	auto server = make_shared<Server>("/config/flexisip_fork_context_db.conf");
	server->start();
	ModuleRouter::setMaxPriorityHandled(sofiasip::MsgSipPriority::Emergency);

	auto receiverClient = make_shared<CoreClient>("sip:provencal_le_gaulois@sip.test.org", server);
	receiverClient->getCore()->setNetworkReachable(false);

	uint isRequestAccepted = 0;
	BellesipUtils bellesipUtils{"0.0.0.0", -1, "TCP",
	                            [&isRequestAccepted](int status) {
		                            if (status != 100) {
			                            BC_ASSERT_EQUAL(status, 202, int, "%i");
			                            isRequestAccepted++;
		                            }
	                            },
	                            nullptr};

	SLOGD << "Step 2: Send messages, in priority disorder.";
	uint messageSent = 0;
	uint reelOrderIndex = 0;
	const auto& priorities = vector<string>{"non-urgent", "emergency", "normal", "urgent", "normal", "emergency"};
	const auto& reelOrders =
	    vector<vector<uint>>{{16, 17, 18}, {1, 2, 3}, {10, 11, 12}, {7, 8, 9}, {13, 14, 15}, {4, 5, 6}};

	for (const auto& priority : priorities) {
		for (const auto orderValue : reelOrders.at(reelOrderIndex)) {
			bellesipUtils.sendRawRequest(getMessagesHeaders(orderValue, priority),
			                             "C'est pas faux "s + to_string(orderValue) + "\r\n\r\n");
			messageSent++;
			auto beforePlus2 = system_clock::now() + 2s;
			while (isRequestAccepted != messageSent && beforePlus2 >= system_clock::now()) {
				bellesipUtils.stackSleep(10);
				server->getAgent()->getRoot()->step(10ms);
			}
		}
		reelOrderIndex++;
	}

	SLOGD << "Step 3: Assert that db fork is still present because device is offline, message fork is destroyed "
	         "because message is saved";
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_TRUE(
	    CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([agent = server->getAgent(), &messageSent] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    return moduleRouter->mStats.mCountMessageForks->finish->read() == messageSent;
	    }));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), messageSent, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->finish->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), messageSent, int, "%i");

	SLOGD << "Step 4: Client REGISTER, then receive message";
	receiverClient->getCore()->setNetworkReachable(true);
	BC_ASSERT_TRUE(CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([receiverClient, &messageSent] {
		return receiverClient->getAccount()->getState() == RegistrationState::Ok &&
		       (uint)receiverClient->getCore()->getUnreadChatMessageCount() == messageSent;
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
	BC_ASSERT_CPP_EQUAL(order - 1, messageSent);

	SLOGD << "Step 6: Check fork stats";
	BC_ASSERT_TRUE(
	    CoreAssert({receiverClient->getCore()}, server->getAgent()).wait([agent = server->getAgent(), &messageSent] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    return moduleRouter->mStats.mCountMessageProxyForks->finish->read() == messageSent;
	    }));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageProxyForks->start->read(), messageSent, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->start->read(), 2 * messageSent, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountMessageForks->finish->read(), 2 * messageSent, int, "%i");
}

namespace {
TestSuite
    _("Fork context mysql",
      {
          TEST_NO_TAG("Unit test fork message repository with mysql", forkMessageContextSociRepositoryMysqlUnitTests),
          TEST_NO_TAG("Unit test fork message with branches repository with mysql",
                      forkMessageContextWithBranchesSociRepositoryMysqlUnitTests),
          TEST_NO_TAG("Unit test fork message repository with mysql, load at startup",
                      forkMessageContextSociRepositoryFullLoadMysqlUnitTests),
          TEST_NO_TAG("Global test ForkMessage with mysql", globalTest),
          TEST_NO_TAG("Global test ForkMessage with mysql, multiple devices", globalTestMultipleDevices),
          TEST_NO_TAG("Test that multiple register in a row do not lead to multiple access in DB",
                      testDBAccessOptimization),
          TEST_NO_TAG("Global test fork message with mysql, db deleted before restoration", globalTestDatabaseDeleted),
          TEST_NO_TAG("Global test ForkMessage with mysql, orderPreservedTest", globalOrderTest),
      },
      Hooks()
          .beforeSuite([] {
	          char const* cHost = getenv("BC_MYSQL_HOST");
	          auto host = (cHost == NULL) ? "" : string(cHost);
	          if (host == "") host = "127.0.0.1";
	          ForkMessageContextSociRepository::prepareConfiguration(
	              "mysql", "db='flexisip_messages' user='belledonne' password='cOmmu2015nicatiOns' host='" + host + "'",
	              10);

	          return 0;
          })
          .beforeEach([] { ForkMessageContextSociRepository::getInstance()->deleteAll(); })
          .afterEach([] {
	          ForkMessageContextSociRepository::getInstance()->deleteAll();
	          RegistrarDb::resetDB();
          }));
}
} // namespace tester
} // namespace flexisip
