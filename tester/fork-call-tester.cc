/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/module-router.hh"

#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;

namespace flexisip {
namespace tester {

static void basicCall() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server);
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server);

	callerClient->call(calleeClient);
	callerClient->endCurrentCall(calleeClient);

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	if (moduleRouter) {
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
		BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 1, int, "%i");
	}
}

static void callWithEarlyCancel() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server);
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server);

	callerClient->callWithEarlyCancel(calleeClient);

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	// Assert Fork is destroyed
	CoreAssert(calleeClient, callerClient, server)
	    .wait([&moduleRouter = *moduleRouter] {
		    FAIL_IF(moduleRouter.mStats.mCountCallForks->start->read() != 1);
		    FAIL_IF(moduleRouter.mStats.mCountCallForks->finish->read() != 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

static void callWithEarlyCancelCalleeOffline() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server);
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server);
	const auto calleeIdleClient = server->clientBuilder().setApplePushConfig().build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientCore = calleeIdleClient.getCore();
	CoreAssert asserter{calleeIdleClientCore, server};

	// Check that call log is empty before test
	if (!BC_ASSERT_TRUE(
	        asserter.wait([&calleeIdleClientCore] { return calleeIdleClientCore->getCallLogs().empty(); }))) {
	}

	calleeIdleClient.disconnect();
	// Call with callee offline with one device
	callerClient->callWithEarlyCancel(calleeClient, nullptr);

	// Assert that fork is still present because callee has one device offline
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0, int, "%i");

	// Callee idle device came back online, sending a new Register
	calleeIdleClient.reconnect();
	// Wait for registration OK and check that call log is not empty anymore
	asserter
	    .wait([&calleeIdleClient] {
		    FAIL_IF(calleeIdleClient.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClient.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received
	BC_ASSERT_TRUE(asserter.wait([&calleeIdleClientCore] {
		return !calleeIdleClientCore->getCurrentCall() ||
		       calleeIdleClientCore->getCurrentCall()->getState() == Call::State::End ||
		       calleeIdleClientCore->getCurrentCall()->getState() == Call::State::Released;
	}));

	// Assert Fork is destroyed
	asserter
	    .wait([&moduleRouter = *moduleRouter] {
		    FAIL_IF(moduleRouter.mStats.mCountCallForks->finish->read() < 1);
		    FAIL_IF(1 < moduleRouter.mStats.mCountCallForks->finish->read());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
}

static void calleeOfflineWithOneDevice() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server);
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server);
	auto calleeClientOfflineDevice =
	    server->clientBuilder().setApplePushConfig().build("sip:calleeClient@sip.test.org");
	auto calleeOfflineDeviceCore = calleeClientOfflineDevice.getCore();

	calleeClientOfflineDevice.disconnect();

	callerClient->call(calleeClient);
	callerClient->endCurrentCall(calleeClient);

	// Assert that fork is still present because not all devices where online
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0, int, "%i");

	// Offline device came back online, sending a new Register
	calleeClientOfflineDevice.reconnect();
	CoreAssert asserter{calleeOfflineDeviceCore, server};
	// Wait for registration OK and check that call log is not empty anymore
	BC_ASSERT_TRUE(asserter.wait([&calleeClientOfflineDevice] {
		return calleeClientOfflineDevice.getAccount()->getState() == RegistrationState::Ok &&
		       !calleeClientOfflineDevice.getCore()->getCallLogs().empty();
	}));

	// Assert CANCEL is received
	BC_ASSERT_TRUE(asserter.wait([&calleeOfflineDeviceCore] {
		return !calleeOfflineDeviceCore->getCurrentCall() ||
		       calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::End ||
		       calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::Released;
	}));

	// Assert Fork is destroyed
	BC_ASSERT_TRUE(asserter.wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountCallForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
}

static void calleeOfflineWithOneDeviceEarlyDecline() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server);
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server);
	auto calleeClientOfflineDevice =
	    server->clientBuilder().setApplePushConfig().build("sip:calleeClient@sip.test.org");
	auto calleeOfflineDeviceCore = calleeClientOfflineDevice.getCore();

	calleeClientOfflineDevice.disconnect();

	callerClient->callWithEarlyDecline(calleeClient);

	// Assert that fork is still present because not all devices where online
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0, int, "%i");

	// Offline device came back online, sending a new Register
	calleeClientOfflineDevice.reconnect();
	CoreAssert asserter{calleeOfflineDeviceCore, server};
	// Wait for registration OK and check that call log is not empty anymore
	BC_ASSERT_TRUE(asserter.wait([&calleeClientOfflineDevice] {
		return calleeClientOfflineDevice.getAccount()->getState() == RegistrationState::Ok &&
		       !calleeClientOfflineDevice.getCore()->getCallLogs().empty();
	}));

	// Assert CANCEL is received
	BC_ASSERT_TRUE(asserter.wait([&calleeOfflineDeviceCore] {
		return !calleeOfflineDeviceCore->getCurrentCall() ||
		       calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::End ||
		       calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::Released;
	}));

	// Assert Fork is destroyed
	BC_ASSERT_TRUE(asserter.wait([agent = server->getAgent()] {
		const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		return moduleRouter->mStats.mCountCallForks->finish->read() == 1;
	}));
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
}

static void calleeMultipleOnlineDevices() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server);
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server);

	vector<shared_ptr<CoreClient>> calleeIdleDevices{};
	for (int i = 0; i < 10; ++i) {
		calleeIdleDevices.emplace_back(make_shared<CoreClient>("sip:calleeClient@sip.test.org", server));
	}

	callerClient->call(calleeClient, nullptr, nullptr, calleeIdleDevices);
	callerClient->endCurrentCall(calleeClient);

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 1, int, "%i");
}

namespace {
TestSuite _("Fork call context suite",
            {
                TEST_NO_TAG("Basic call -> terminate", basicCall),
                TEST_NO_TAG("Call with early cancel", callWithEarlyCancel),
                TEST_NO_TAG("Call with early decline", calleeOfflineWithOneDeviceEarlyDecline),
                TEST_NO_TAG("Call an offline user, early cancel", callWithEarlyCancelCalleeOffline),
                TEST_NO_TAG("Call an online user, with an other offline device", calleeOfflineWithOneDevice),
                TEST_NO_TAG("Call an online user, with other idle devices", calleeMultipleOnlineDevices),
            });
}
} // namespace tester
} // namespace flexisip
