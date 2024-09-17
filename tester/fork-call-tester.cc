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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <chrono>

#include "flexisip/module-router.hh"
#include "fork-context/fork-call-context.hh"

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

namespace flexisip::tester {
namespace {

void basicCall() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");

	BC_ASSERT_PTR_NOT_NULL(callerClient.call(calleeClient));
	BC_ASSERT(callerClient.endCurrentCall(calleeClient));

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	if (moduleRouter) {
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
		BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 1);
	}
}

void callWithEarlyCancel() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");

	BC_ASSERT_PTR_NOT_NULL(callerClient.callWithEarlyCancel(calleeClient));

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	// Assert Fork is destroyed
	CoreAssert(server, callerClient, calleeClient)
	    .wait([&moduleRouter = *moduleRouter] {
		    FAIL_IF(moduleRouter.mStats.mCountCallForks->start->read() != 1);
		    FAIL_IF(moduleRouter.mStats.mCountCallForks->finish->read() != 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
}

void callWithEarlyCancelCalleeOffline() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	const auto calleeIdleClient = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	// Check that call log is empty before test.
	CoreAssert asserter{server, callerClient, calleeClient, calleeIdleClient};
	asserter
	    .wait([&calleeIdleClientCore = calleeIdleClient.getCore()] {
		    return LOOP_ASSERTION(calleeIdleClientCore->getCallLogs().empty());
	    })
	    .assert_passed();
	calleeIdleClient.disconnect();

	// Call with callee offline with one device.
	BC_ASSERT_PTR_NOT_NULL(callerClient.callWithEarlyCancel(calleeClient));

	// Assert that fork is still present because callee has one device offline.
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0);

	// Callee idle device came back online, sending a new Register.
	calleeIdleClient.reconnect();
	// Wait for registration OK and check that call log is not empty anymore.
	asserter
	    .wait([&calleeIdleClient] {
		    FAIL_IF(calleeIdleClient.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClient.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received.
	asserter
	    .wait([&calleeIdleClientCore = calleeIdleClient.getCore()] {
		    return LOOP_ASSERTION(!calleeIdleClientCore->getCurrentCall() ||
		                          calleeIdleClientCore->getCurrentCall()->getState() == Call::State::End ||
		                          calleeIdleClientCore->getCurrentCall()->getState() == Call::State::Released);
	    })
	    .assert_passed();

	// Assert Fork is destroyed.
	asserter
	    .wait([&moduleRouter = *moduleRouter] {
		    FAIL_IF(moduleRouter.mStats.mCountCallForks->finish->read() < 1);
		    FAIL_IF(1 < moduleRouter.mStats.mCountCallForks->finish->read());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
}

/**
 * The goal of this test is to ensure that with fork-late mode "on" for calls, when a call is cancelled early, even
 * without any "good" response (!= 408/503), we immediately return a terminal response.
 *
 * To do that, we start a call between a caller and a callee that has only one offline client (iOS client).
 * The caller quickly terminates the call, and we assert that a terminal (503) response is received.
 * We then reconnect the iOS client to check that ForkCall was well preserved to send INVITE/CANCEL to the iOS client.
 */
void callWithEarlyCancelCalleeOnlyOffline() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	const auto callerClient = builder.build("sip:callerClient@sip.test.org");
	const auto calleeIdleClient = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	// Check that call log is empty before test.
	CoreAssert asserter{server, callerClient, calleeIdleClient};
	asserter
	    .wait([&calleeIdleClientCore = calleeIdleClient.getCore()] {
		    return LOOP_ASSERTION(calleeIdleClientCore->getCallLogs().empty());
	    })
	    .assert_passed();
	calleeIdleClient.disconnect();

	bool isRequestAccepted = false;
	bool is503Received = false;
	bool isCancelRequestAccepted = false;
	BellesipUtils belleSipUtils{"127.0.0.1", BELLE_SIP_LISTENING_POINT_RANDOM_PORT, "TCP",
	                            [&isRequestAccepted, &is503Received, &isCancelRequestAccepted](int status) {
		                            if (status == 100) isRequestAccepted = true;
		                            if (!isRequestAccepted) return;

		                            if (status == 503) is503Received = true;
		                            if (status == 200) isCancelRequestAccepted = true;
	                            },
	                            nullptr};
	asserter.registerSteppable(belleSipUtils);

	stringstream rawRequest{};
	rawRequest
	    << "INVITE sip:calleeClient@sip.test.org SIP/2.0\r\n"
	    << "Via: SIP/2.0/TCP 127.0.0.1:" << belleSipUtils.getListeningPort() << ";branch=z9hG4bK.L~E42YLQ0\r\n"
	    << "From: sip:callerClient@sip.test.org;tag=6er0DzzuB\r\n"
	    << "To: sip:calleeClient@sip.test.org\r\n"
	    << "CSeq: 20 INVITE\r\n"
	    << "Call-ID: AMVyfHFNUI\r\n"
	    << "Max-Forwards: 70\r\n"
	    << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
	    << "Supported: replaces, outbound, gruu, path\r\n"
	    << "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\n"
	    << "Content-Type: application/sdp\r\n"
	    << "Contact: "
	       "<sip:callerClient@sip.test.org>;+sip.instance=\"<urn:uuid:6e87dc22-b1bc-00ff-b0ab-cc59670f7cdd>\"\r\n"
	    << "User-Agent: BelleSipUtils\r\n"
	    << "Content-Length: 0\r\n\r\n";
	belleSipUtils.sendRawRequest(rawRequest.str());

	asserter.wait([&isRequestAccepted]() { return LOOP_ASSERTION(isRequestAccepted == true); }).hard_assert_passed();

	// Server can need one more loop to receive 503 after sending 100 trying.
	server.getRoot()->step(1ms);

	rawRequest = {};
	rawRequest << "CANCEL sip:calleeClient@sip.test.org SIP/2.0\r\n"
	           << "Via: SIP/2.0/TCP 127.0.0.1:" << belleSipUtils.getListeningPort() << ";branch=z9hG4bK.L~E42YLQ0\r\n"
	           << "From: <sip:callerClient@sip.test.org>;tag=6er0DzzuB\r\n"
	           << "To: <sip:calleeClient@sip.test.org>\r\n"
	           << "CSeq: 20 CANCEL\r\n"
	           << "Call-ID: AMVyfHFNUI\r\n"
	           << "Max-Forwards: 70\r\n"
	           << "Route: <sip:127.0.0.1:" << server.getFirstPort() << ";transport=tcp;lr>\r\n"
	           << "User-Agent: BelleSipUtils\r\n"
	           << "Content-Length: 0\r\n\r\n";
	belleSipUtils.sendRawRequest(rawRequest.str());

	asserter
	    .wait([&isCancelRequestAccepted, &is503Received]() {
		    FAIL_IF(isCancelRequestAccepted != true);
		    FAIL_IF(is503Received != true);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Assert that fork is still present because callee has only offline devices.
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0);

	// Callee idle device came back online, sending a new Register.
	calleeIdleClient.reconnect();
	// Wait for registration OK and check that call log is not empty anymore.
	asserter
	    .wait([&calleeIdleClient] {
		    FAIL_IF(calleeIdleClient.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClient.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received.
	asserter
	    .wait([&calleeIdleClientCore = calleeIdleClient.getCore()] {
		    return LOOP_ASSERTION(!calleeIdleClientCore->getCurrentCall() ||
		                          calleeIdleClientCore->getCurrentCall()->getState() == Call::State::End ||
		                          calleeIdleClientCore->getCurrentCall()->getState() == Call::State::Released);
	    })
	    .assert_passed();

	// Assert Fork is destroyed.
	asserter
	    .wait([&moduleRouter = *moduleRouter] {
		    return LOOP_ASSERTION(moduleRouter.mStats.mCountCallForks->finish->read() == 1);
	    })
	    .assert_passed();

	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
}

/**
 * Reconnect two apple devices, one with voip push available and one not, after an early cancel.
 * Assert that only the device with voip push receive an INVITE+CANCEL on register.
 */
void callWithEarlyCancelCalleeOfflineNoVOIPPush() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	auto calleeIdleClientVoip = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");
	auto calleeIdleClientRemote = builder.setApplePushConfigRemoteOnly().build("sip:calleeClient@sip.test.org");

	// Prepare asserter.
	const auto calleeIdleClientVoipCore = calleeIdleClientVoip.getCore();
	const auto calleeIdleClientRemoteCore = calleeIdleClientVoip.getCore();

	// Check that call log is empty before test.
	BC_HARD_ASSERT_TRUE(calleeIdleClientVoipCore->getCallsNb() == 0);
	BC_HARD_ASSERT_TRUE(calleeIdleClientRemoteCore->getCallsNb() == 0);

	// Call with callee offline with two device.
	calleeIdleClientVoip.disconnect();
	calleeIdleClientRemote.disconnect();
	BC_ASSERT_PTR_NOT_NULL(callerClient.callWithEarlyCancel(calleeClient));

	// Assert that fork is still present because callee has two devices offline.
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0);

	// Callee idle devices came back online, sending a new Register.
	calleeIdleClientVoip.reconnect();
	calleeIdleClientRemote.reconnect();
	// Wait for registration OK and check that call log is not empty anymore for client with VOIP push.
	CoreAssert asserter{server, callerClient, calleeClient, calleeIdleClientVoip, calleeIdleClientRemote};
	asserter
	    .wait([&calleeIdleClientVoip, &calleeIdleClientRemote] {
		    FAIL_IF(calleeIdleClientVoip.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClientRemote.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeIdleClientVoip.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received client with VOIP push.
	asserter
	    .wait([&calleeIdleClientVoipCore] {
		    return LOOP_ASSERTION(!calleeIdleClientVoipCore->getCurrentCall() ||
		                          calleeIdleClientVoipCore->getCurrentCall()->getState() == Call::State::End ||
		                          calleeIdleClientVoipCore->getCurrentCall()->getState() == Call::State::Released);
	    })
	    .assert_passed();

	// Assert call log is still empty for client with remote push only.
	asserter
	    .wait([&calleeIdleClientRemote] {
		    return LOOP_ASSERTION(calleeIdleClientRemote.getCore()->getCallLogs().empty());
	    })
	    .assert_passed();

	// Fork not destroyed because a branch stay alive forever. Destroyed on timeout or Agent destruction.
}

void calleeOfflineWithOneDevice() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	auto calleeClientOfflineDevice = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	const auto calleeOfflineDeviceCore = calleeClientOfflineDevice.getCore();
	calleeClientOfflineDevice.disconnect();

	BC_ASSERT_PTR_NOT_NULL(callerClient.call(calleeClient));
	BC_ASSERT(callerClient.endCurrentCall(calleeClient));

	// Assert that fork is still present because not all devices where online.
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0);

	// Offline device came back online, sending a new Register.
	calleeClientOfflineDevice.reconnect();
	// Wait for registration OK and check that call log is not empty anymore.
	CoreAssert asserter{server, callerClient, calleeClient, calleeClientOfflineDevice};
	asserter
	    .wait([&calleeClientOfflineDevice] {
		    FAIL_IF(calleeClientOfflineDevice.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeClientOfflineDevice.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received.
	asserter
	    .wait([&calleeOfflineDeviceCore] {
		    return LOOP_ASSERTION(!calleeOfflineDeviceCore->getCurrentCall() ||
		                          calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::End ||
		                          calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::Released);
	    })
	    .assert_passed();

	// Assert Fork is destroyed.
	asserter
	    .wait([agent = server.getAgent()] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    FAIL_IF(moduleRouter->mStats.mCountCallForks->finish->read() != 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
}

void calleeOfflineWithOneDeviceEarlyDecline() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");
	auto calleeClientOfflineDevice = builder.setApplePushConfig().build("sip:calleeClient@sip.test.org");

	const auto calleeOfflineDeviceCore = calleeClientOfflineDevice.getCore();
	calleeClientOfflineDevice.disconnect();

	BC_ASSERT_PTR_NOT_NULL(callerClient.callWithEarlyDecline(calleeClient));

	// Assert that fork is still present because not all devices where online.
	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 0);

	// Offline device came back online, sending a new Register.
	calleeClientOfflineDevice.reconnect();
	// Wait for registration OK and check that call log is not empty anymore.
	CoreAssert asserter{server, callerClient, calleeClient, calleeClientOfflineDevice};
	asserter
	    .wait([&calleeClientOfflineDevice] {
		    FAIL_IF(calleeClientOfflineDevice.getAccount()->getState() != RegistrationState::Ok);
		    FAIL_IF(calleeClientOfflineDevice.getCore()->getCallLogs().empty());
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert CANCEL is received.
	asserter
	    .wait([&calleeOfflineDeviceCore] {
		    return LOOP_ASSERTION(!calleeOfflineDeviceCore->getCurrentCall() ||
		                          calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::End ||
		                          calleeOfflineDeviceCore->getCurrentCall()->getState() == Call::State::Released);
	    })
	    .assert_passed();

	// Assert Fork is destroyed.
	asserter
	    .wait([agent = server.getAgent()] {
		    const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(agent->findModule("Router"));
		    FAIL_IF(moduleRouter->mStats.mCountCallForks->finish->read() != 1);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
}

void calleeMultipleOnlineDevices() {
	Server server{"/config/flexisip_fork_call_context.conf"};
	server.start();

	ClientBuilder builder{*server.getAgent()};
	auto callerClient = builder.build("sip:callerClient@sip.test.org");
	auto calleeClient = builder.build("sip:calleeClient@sip.test.org");

	vector<shared_ptr<CoreClient>> calleeIdleDevices{};
	for (int i = 0; i < 10; ++i) {
		calleeIdleDevices.emplace_back(builder.make("sip:calleeClient@sip.test.org"));
	}

	BC_ASSERT_PTR_NOT_NULL(callerClient.call(calleeClient, nullptr, nullptr, calleeIdleDevices));
	BC_ASSERT(callerClient.endCurrentCall(calleeClient));

	const auto& moduleRouter = dynamic_pointer_cast<ModuleRouter>(server.getAgent()->findModule("Router"));
	BC_ASSERT_PTR_NOT_NULL(moduleRouter);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->start->read(), 1);
	BC_ASSERT_CPP_EQUAL(moduleRouter->mStats.mCountCallForks->finish->read(), 1);
}

struct BrCancelListener : public BranchInfoListener {
	void onBranchCanceled(const std::shared_ptr<BranchInfo>&, ForkStatus cancelStatus) noexcept override {
		mCancelStatus = cancelStatus;
	}
	optional<ForkStatus> mCancelStatus{};
};

/**
 * Verify that the cancellation status is linked to the cancellation reason.
 */
void cancelStatusOnCancel() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "localhost"},
	    {"module::Router/enabled", "true"},
	}};
	proxy.start();
	const auto moduleRouter = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModule("Router"));

	const auto cancel = [&proxy, &moduleRouter](const string& reason) {
		ostringstream rawSipCancel{};
		rawSipCancel << "CANCEL sip:callee1@127.0.0.1:5360 SIP/2.0 \r\n"
		             << "Via: SIP/2.0/TLS 127.0.0.1;rport=5360\r\n"
		             << "From: <sip:caller@127.0.0.1>;tag=465687829\r\n"
		             << "To: <sip:callee1@127.0.0.1>\r\n"
		             << "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
		             << "CSeq: 1 CANCEL\r\n"
		             << reason << "Content-Length: 0\r\n\r\n";

		auto ev = make_shared<RequestSipEvent>(proxy.getAgent(), make_shared<MsgSip>(0, rawSipCancel.str()));
		ev->setEventLog(make_shared<CallLog>(ev->getMsgSip()->getSip()));
		auto forkCallCtx = ForkCallContext::make(moduleRouter, ev, sofiasip::MsgSipPriority::Urgent);
		auto branch = forkCallCtx->addBranch(
		    ev, make_shared<ExtendedContact>(SipUri{"sip:callee1@127.0.0.1:5360"}, "sip:127.0.0.1;transport=udp", ""));
		auto branchListener = make_shared<BrCancelListener>();
		branch->mListener = branchListener;
		forkCallCtx->onCancel(ev);
		return branchListener->mCancelStatus;
	};

	{
		const auto cancelStatus = cancel("Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n");
		BC_HARD_ASSERT(cancelStatus.has_value());
		BC_ASSERT(cancelStatus.value() == ForkStatus::AcceptedElsewhere);
	}
	{
		const auto cancelStatus = cancel("Reason: SIP;cause=600;text=\"Busy Everywhere\"\r\n");
		BC_HARD_ASSERT(cancelStatus.has_value());
		BC_ASSERT(cancelStatus.value() == ForkStatus::DeclinedElsewhere);
	}
	// Check the default behavior if reason is not given.
	{
		const auto cancelStatus = cancel("");
		BC_HARD_ASSERT(cancelStatus.has_value());
		BC_ASSERT(cancelStatus.value() == ForkStatus::Standard);
	}
}

/**
 * Check that an accepted call on a branch leads to a cancel with AcceptedElseWhere status on another branch.
 */
void cancelStatusOnResponse() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "localhost"},
	    {"module::Router/enabled", "true"},
	}};
	proxy.start();
	const auto moduleRouter = dynamic_pointer_cast<ModuleRouter>(proxy.getAgent()->findModule("Router"));

	const string rawSipInvite =
	    "INVITE sip:callee@127.0.0.1:5360;pn-prid=EA88:remote;pn-provider=apns.dev;pn-param=XX.example.org SIP/2.0\r\n"
	    "Via: SIP/2.0/TLS 127.0.0.1;rport=5360\r\n"
	    "From: <sip:caller@127.0.0.1>;tag=465687829\r\n"
	    "To: <sip:callee@127.0.0.1>\r\n"
	    "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	    "CSeq: 1 INVITE\r\n"
	    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\n"
	    "Content-Type: application/sdp\r\n"
	    "Content-Length: 0\r\n\r\n";

	auto ev = make_shared<RequestSipEvent>(proxy.getAgent(), make_shared<MsgSip>(0, rawSipInvite));
	ev->setEventLog(make_shared<CallLog>(ev->getMsgSip()->getSip()));
	auto forkCallCtx = ForkCallContext::make(moduleRouter, ev, sofiasip::MsgSipPriority::Urgent);
	// add a branch to ForkCallCtx
	auto branch = forkCallCtx->addBranch(
	    ev, make_shared<ExtendedContact>(SipUri{"sip:callee@127.0.0.1:5360"}, "sip:127.0.0.1;transport=udp", ""));

	auto branchListener = make_shared<BrCancelListener>();
	branch->mListener = branchListener;

	// create a response on another branch
	const string rawSipResponse = "SIP/2.0 200 Ok\r\n"
	                              "Via: SIP/2.0/TLS 127.0.0.1;rport=5360\r\n"
	                              "From: <sip:caller@127.0.0.1>;tag=465687829\r\n"
	                              "To: <sip:callee2@127.0.0.1>\r\n"
	                              "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
	                              "CSeq: 1 INVITE\r\n"
	                              "Allow: INVITE, ACK, CANCEL\r\n"
	                              "Contact: <sip:callee2@127.0.0.1>\r\n"
	                              "Content-Type: application/sdp\r\n"
	                              "Content-Length: 0\r\n\r\n";
	auto response = make_shared<ResponseSipEvent>(proxy.getAgent(), make_shared<MsgSip>(0, rawSipResponse));
	auto answeredBranch = BranchInfo::make(forkCallCtx);
	((ForkContext*)(forkCallCtx.get()))->onResponse(answeredBranch, response);

	BC_HARD_ASSERT(branchListener->mCancelStatus.has_value());
	BC_ASSERT(branchListener->mCancelStatus.value() == ForkStatus::AcceptedElsewhere);
}

TestSuite _("ForkCallContext",
            {
                CLASSY_TEST(basicCall),
                CLASSY_TEST(callWithEarlyCancel),
                CLASSY_TEST(calleeOfflineWithOneDeviceEarlyDecline),
                CLASSY_TEST(callWithEarlyCancelCalleeOffline),
                CLASSY_TEST(callWithEarlyCancelCalleeOnlyOffline),
                CLASSY_TEST(calleeOfflineWithOneDevice),
                CLASSY_TEST(calleeMultipleOnlineDevices),
                CLASSY_TEST(callWithEarlyCancelCalleeOfflineNoVOIPPush),
                CLASSY_TEST(cancelStatusOnCancel),
                CLASSY_TEST(cancelStatusOnResponse),
            });

} // namespace
} // namespace flexisip::tester