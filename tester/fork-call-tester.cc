/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;

namespace flexisip {
namespace tester {

static void basicCall() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());

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

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());

	callerClient->callWithEarlyCancel(calleeClient);

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	// Assert Fork is destroyed
	CoreAssert(calleeClient, callerClient, server->getAgent())
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

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());
	const auto calleeIdleClient =
	    ClientBuilder(*server->getAgent()).setApplePushConfig().build("sip:calleeClient@sip.test.org");
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

/**
 * The goal of this test is to ensure that with fork-late mode "on" for calls, when a call is cancelled early, even
 * without any "good" response (!= 408/503), we immediately return a terminal response.
 *
 * To do that, we start a call between a caller and a callee that has only one offline client (iOS client).
 * The caller quickly terminates the call, and we assert that a terminal (503) response is received.
 * We then reconnect the iOS client to check that ForkCall was well preserved to send INVITE/CANCEL to the iOS client.
 */
static void callWithEarlyCancelCalleeOnlyOffline() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	const auto calleeIdleClient =
	    ClientBuilder(*server->getAgent()).setApplePushConfig().build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientCore = calleeIdleClient.getCore();
	CoreAssert asserter{calleeIdleClientCore, server};

	// Check that call log is empty before test
	asserter.wait([&calleeIdleClientCore] { return calleeIdleClientCore->getCallLogs().empty(); }).assert_passed();
	calleeIdleClient.disconnect();

	bool isRequestAccepted = false;
	bool is503Received = false;
	bool isCancelRequestAccepted = false;
	BellesipUtils inviteTransaction{"127.0.0.1", 56492, "TCP",
	                                [&isRequestAccepted, &is503Received, &isCancelRequestAccepted](int status) {
		                                if (status == 100) isRequestAccepted = true;
		                                if (!isRequestAccepted) return;

		                                if (status == 503) is503Received = true;
		                                if (status == 200) isCancelRequestAccepted = true;
	                                },
	                                nullptr};
	asserter.registerSteppable(inviteTransaction);

	// Call with callee offline with all device
	inviteTransaction.sendRawRequest(
	    "INVITE sip:calleeClient@sip.test.org SIP/2.0\r\n"
	    "Via: SIP/2.0/TCP 127.0.0.1:56492;branch=z9hG4bK.L~E42YLQ0;rport\r\n"
	    "From: sip:callerClient@sip.test.org;tag=6er0DzzuB\r\n"
	    "To: sip:calleeClient@sip.test.org\r\n"
	    "CSeq: 20 INVITE\r\n"
	    "Call-ID: AMVyfHFNUI\r\n"
	    "Max-Forwards: 70\r\n"
	    "Route: <sip:127.0.0.1:5760;transport=tcp;lr>\r\n"
	    "Supported: replaces, outbound, gruu, path\r\n"
	    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\n"
	    "Content-Type: application/sdp\r\n"
	    "Contact: "
	    "<sip:callerClient@sip.test.org;gr=urn:uuid:6e87dc22-b1bc-00ff-b0ab-cc59670f7cdd;>+sip.instance=\"urn:uuid:"
	    "6e87dc22-b1bc-00ff-b0ab-cc59670f7cdd\";+org.linphone.specs=\"lime\"\r\n"
	    "User-Agent: BelleSipUtils for Flexisip tests\r\n");

	BC_HARD_ASSERT(asserter.wait([&isRequestAccepted]() {
		FAIL_IF(isRequestAccepted != true);
		return ASSERTION_PASSED();
	}));

	// Server can need one more loop to receive 503 after sending 100 trying
	server->getRoot()->step(1ms);

	inviteTransaction.sendRawRequest("CANCEL sip:calleeClient@sip.test.org SIP/2.0\r\n"
	                                 "Via: SIP/2.0/TCP 127.0.0.1:56492;branch=z9hG4bK.L~E42YLQ0;rport\r\n"
	                                 "Call-ID: AMVyfHFNUI\r\n"
	                                 "From: <sip:callerClient@sip.test.org>;tag=6er0DzzuB\r\n"
	                                 "To: <sip:calleeClient@sip.test.org>\r\n"
	                                 "Route: <sip:127.0.0.1:5760;transport=tcp;lr>\r\n"
	                                 "Max-Forwards: 70\r\n"
	                                 "CSeq: 20 CANCEL\r\n"
	                                 "User-Agent: BelleSipUtils for Flexisip tests\r\n"
	                                 "Content-Length: 0");

	BC_HARD_ASSERT(asserter.wait([&isCancelRequestAccepted, &is503Received]() {
		FAIL_IF(isCancelRequestAccepted != true);
		FAIL_IF(is503Received != true);
		return ASSERTION_PASSED();
	}));

	// Assert that fork is still present because callee has only offline devices
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
		    LOOP_ASSERTION(moduleRouter.mStats.mCountCallForks->finish->read() == 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
}

/**
 * Reconnect two apple devices, one with voip push available and one not, after an early cancel.
 * Assert that only the device with voip push receive an INVITE+CANCEL on register.
 */
static void callWithEarlyCancelCalleeOfflineNoVOIPPush() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());
	const auto calleeIdleClientVoip =
	    ClientBuilder(*server->getAgent()).setApplePushConfig().build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClientRemote =
	    ClientBuilder(*server->getAgent()).setApplePushConfigRemoteOnly().build("sip:calleeClient@sip.test.org");

	// Prepare asserter
	const auto calleeIdleClientVoipCore = calleeIdleClientVoip.getCore();
	const auto calleeIdleClientRemoteCore = calleeIdleClientVoip.getCore();
	CoreAssert asserter{calleeIdleClientVoip.getCore(), calleeIdleClientRemote.getCore(), server};

	// Check that call log is empty before test
	BC_HARD_ASSERT_TRUE(calleeIdleClientVoipCore->getCallsNb() == 0);
	BC_HARD_ASSERT_TRUE(calleeIdleClientRemoteCore->getCallsNb() == 0);

	// Call with callee offline with two device
	calleeIdleClientVoip.disconnect();
	calleeIdleClientRemote.disconnect();
	callerClient->callWithEarlyCancel(calleeClient, nullptr);

	// Assert that fork is still present because callee has two devices offline
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server->getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1, int, "%i");
	BC_ASSERT_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0, int, "%i");

	// Callee idle devices came back online, sending a new Register
	calleeIdleClientVoip.reconnect();
	calleeIdleClientRemote.reconnect();
	// Wait for registration OK and check that call log is not empty anymore for client with VOIP push
	asserter
	    .wait([&calleeIdleClientVoip, &calleeIdleClientRemote] {
		    FAIL_IF(calleeIdleClientVoip.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClientRemote.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClientVoip.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received client with VOIP push
	BC_ASSERT_TRUE(asserter.wait([&calleeIdleClientVoipCore] {
		return !calleeIdleClientVoipCore->getCurrentCall() ||
		       calleeIdleClientVoipCore->getCurrentCall()->getState() == Call::State::End ||
		       calleeIdleClientVoipCore->getCurrentCall()->getState() == Call::State::Released;
	}));

	// Assert call log is still empty for client with remote push only.
	asserter
	    .wait([&calleeIdleClientRemote] {
		    FAIL_IF(!calleeIdleClientRemote.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Fork not destroyed because a branch stay alive forever. Destroyed on timeout or Agent destruction.
}

static void calleeOfflineWithOneDevice() {
	auto server = make_shared<Server>("/config/flexisip_fork_call_context.conf");
	server->start();

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());
	auto calleeClientOfflineDevice =
	    ClientBuilder(*server->getAgent()).setApplePushConfig().build("sip:calleeClient@sip.test.org");
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

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());
	auto calleeClientOfflineDevice =
	    ClientBuilder(*server->getAgent()).setApplePushConfig().build("sip:calleeClient@sip.test.org");
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

	auto callerClient = make_shared<CoreClient>("sip:callerClient@sip.test.org", server->getAgent());
	auto calleeClient = make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent());

	vector<shared_ptr<CoreClient>> calleeIdleDevices{};
	for (int i = 0; i < 10; ++i) {
		calleeIdleDevices.emplace_back(make_shared<CoreClient>("sip:calleeClient@sip.test.org", server->getAgent()));
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
                TEST_NO_TAG("Call an only offline user, early cancel", callWithEarlyCancelCalleeOnlyOffline),
                TEST_NO_TAG("Call an online user, with an other offline device", calleeOfflineWithOneDevice),
                TEST_NO_TAG("Call an online user, with other idle devices", calleeMultipleOnlineDevices),
                CLASSY_TEST(callWithEarlyCancelCalleeOfflineNoVOIPPush),
            });
}
} // namespace tester
} // namespace flexisip
