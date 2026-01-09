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

#include <map>
#include <memory>
#include <string>

#include "bctoolbox/tester.h"
#include "linphone++/call.hh"

#include "utils/asserts.hh"
#include "utils/call-assert.hh"
#include "utils/call-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

using namespace std;

namespace flexisip::tester {
namespace {

std::map<std::string, std::string> sServerConfig = {
    {"global/transports", "sip:127.0.0.1:0;transport=tcp sip:[::1]:0;transport=tcp"},
    {"module::MediaRelay/enabled", "false"},
    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to the local network
    {"module::Registrar/enabled", "true"},
    {"module::Registrar/reg-domains", "sip.example.org"},
};

struct ContextSettings {
	size_t numberOfCallerDevices{1};
	size_t numberOfCalleeDevices{1};
	size_t numberOfCalleeIdleDevices{1};
	string callerUri{"sip:caller@sip.example.org"};
	string calleeUri{"sip:callee@sip.example.org"};
	string customModuleInjectAfter{"SanityChecker"};
	OnOff videoCall{OnOff::On};
	CallAssertionInfo::MediaStateList inCallMediaState{CallAssert<>::kAllMediaSentReceived};
};

class CallTestContext {
public:
	explicit CallTestContext(const ContextSettings& settings = {})
	    : params(settings),
	      customModule(InjectedHooks{
	          params.customModuleInjectAfter,
	          [&](std::unique_ptr<RequestSipEvent>&& ev) { return customModuleRequestCallback(std::move(ev)); },
	      }),
	      server(sServerConfig, &customModule) {
		server.start();

		ClientBuilder builder{*server.getAgent()};
		builder.setVideoReceive(OnOff::On).setVideoSend(OnOff::On);
		for (size_t i = 0; i < params.numberOfCallerDevices; i++) {
			callerDevices.push_back(builder.make(params.callerUri + ";device=n"s + to_string(i)));
		}
		for (size_t i = 0; i < params.numberOfCalleeDevices; i++) {
			calleeDevices.push_back(builder.make(params.calleeUri + ";device=n"s + to_string(i)));
		}
		for (size_t i = 0; i < params.numberOfCalleeIdleDevices; i++) {
			calleeIdleDevices.push_back(builder.make(params.calleeUri + ";device=idle-n"s + to_string(i)));
		}

		asserter.registerSteppable(server);
		asserter.registerSteppables(callerDevices);
		asserter.registerSteppables(calleeDevices);
		asserter.registerSteppables(calleeIdleDevices);

		// Assert all clients registered without issue.
		for (const auto& calleeDevice : calleeDevices) {
			BC_HARD_ASSERT(calleeDevice != nullptr);
			BC_HARD_ASSERT_TRUE(calleeDevice->isRegistered(asserter));
		}
		for (const auto& callerDevice : callerDevices) {
			BC_HARD_ASSERT(callerDevice != nullptr);
			BC_HARD_ASSERT_TRUE(callerDevice->isRegistered(asserter));
		}
		for (const auto& calleeIdleDevice : calleeIdleDevices) {
			BC_HARD_ASSERT(calleeIdleDevice != nullptr);
			BC_HARD_ASSERT_TRUE(calleeIdleDevice->isRegistered(asserter));
			calleeIdleDevice->disconnect();
		}
	}

	InjectedHooks::OnRequestCallback customModuleRequestCallback = [](std::unique_ptr<RequestSipEvent>&& ev) {
		return std::move(ev);
	};

	ContextSettings params;
	InjectedHooks customModule;
	Server server;
	CoreAssert<> asserter{};
	vector<shared_ptr<CoreClient>> callerDevices{};
	vector<shared_ptr<CoreClient>> calleeDevices{};
	vector<shared_ptr<CoreClient>> calleeIdleDevices{};
	optional<ClientCall> answeringCall{};
	vector<ClientCall> otherDevicesCalls{};
};

CallTestContext&& basicCallTemplate(CallTestContext&& ctx) {
	const auto callBuilder = ctx.callerDevices.front()->callBuilder().setVideo(ctx.params.videoCall);
	auto callerCall = callBuilder.call(ctx.params.calleeUri);
	BC_HARD_ASSERT(callerCall.has_value());

	// Assert that every callee received the call, then choose a device to answer the call.
	for (const auto& calleeDevice : ctx.calleeDevices) {
		BC_HARD_ASSERT_TRUE(calleeDevice->hasReceivedCallFrom(*ctx.callerDevices.front(), ctx.asserter));
		auto calleeCall = calleeDevice->getCurrentCall();
		BC_HARD_ASSERT(calleeCall.has_value());

		if (!ctx.answeringCall.has_value()) ctx.answeringCall = std::move(calleeCall);
		else ctx.otherDevicesCalls.push_back(std::move(calleeCall.value()));
	}

	// Accept the call.
	auto callStatus = ctx.answeringCall->accept();
	BC_HARD_ASSERT_CPP_EQUAL(callStatus, 0);

	// Assert the call is running fine.
	CallAssert<>::CallAssertionInfoList callStates = {
	    {*callerCall, linphone::Call::State::StreamsRunning, ctx.params.inCallMediaState},
	    {*ctx.answeringCall, linphone::Call::State::StreamsRunning, ctx.params.inCallMediaState},
	};
	for (const auto& otherDevicesCall : ctx.otherDevicesCalls) {
		callStates.push_back({otherDevicesCall, linphone::Call::State::Released, CallAssert<>::kNoMedia});
	}
	CallAssert{ctx.asserter}.waitUntil(callStates).hard_assert_passed();

	return std::move(ctx);
}

/**
 * From an ongoing call, trigger a call update from the caller, then immediately ask to cancel it because of a network
 * change. In the end, the call is running fine as the caller sent again a call update and everything went back to
 * normal (see RFC 6141 5.5).
 */
CallTestContext&& cancelCallUpdateTemplate(CallTestContext&& ctx) {
	class DeferCallUpdateListener : public linphone::CallListener {
	public:
		using CallListener::CallListener;

		void onStateChanged(const std::shared_ptr<linphone::Call>& call,
		                    linphone::Call::State state,
		                    const std::string&) override {
			if (state == linphone::Call::State::UpdatedByRemote) {
				call->deferUpdate(); // Do not update immediately so the CANCEL request can reach the callee.
				sessionUpdateReceived = true;
			}
		}

		bool sessionUpdateReceived{};
	};

	const auto calleeListener = make_shared<DeferCallUpdateListener>();
	const auto calleeCall = ctx.answeringCall;
	BC_HARD_ASSERT(calleeCall.has_value());
	calleeCall->addListener(calleeListener);

	const auto caller = ctx.callerDevices.front();
	BC_HARD_ASSERT(caller != nullptr);
	const auto callerCall = caller->getCurrentCall();
	BC_HARD_ASSERT(callerCall.has_value());

	// Try to update the current call...
	callerCall->update([](shared_ptr<linphone::CallParams>&& params) {
		params->addCustomHeader("Contact", "sip:new-contact-to-trigger-call-update@sip.example.org");
		return std::move(params);
	});
	// ... but then, trigger a cancellation of the call update.
	caller->getCore()->setNetworkReachable(false);
	caller->getCore()->setNetworkReachable(true);

	optional<bool> eventTerminated{nullopt};
	optional<bool> cancelRequestPassedRouterModule{nullopt};
	ctx.customModuleRequestCallback = [&](unique_ptr<RequestSipEvent>&& ev) {
		if (const auto& msg = ev->getMsgSip(); msg->getSipMethod() != sip_method_cancel ||
		                                       msg->getCallID() != callerCall->getCallId() || !msg->isInDialog()) {

			return std::move(ev);
		}

		cancelRequestPassedRouterModule = true;
		eventTerminated = ev->isTerminated();

		return std::move(ev);
	};

	ctx.asserter
	    .wait([&] {
		    // The re-INVITE request is received by the callee.
		    FAIL_IF(calleeListener->sessionUpdateReceived == false);
		    // The CANCEL request was not replied by the module::Router.
		    FAIL_IF(cancelRequestPassedRouterModule.has_value() == false);
		    FAIL_IF(cancelRequestPassedRouterModule == false);
		    // The associated event is not terminated.
		    FAIL_IF(eventTerminated.has_value() == false);
		    FAIL_IF(eventTerminated == true);
		    return ASSERTION_PASSED();
	    })
	    .assert_passed();

	// Assert the call is running fine.
	CallAssert{ctx.asserter}
	    .waitUntil({
	        {*callerCall, linphone::Call::State::StreamsRunning, ctx.params.inCallMediaState},
	        {*calleeCall, linphone::Call::State::StreamsRunning, ctx.params.inCallMediaState},
	    })
	    .hard_assert_passed();

	return std::move(ctx);
}

void audioOnlyCall() {
	basicCallTemplate(CallTestContext{{.videoCall = OnOff::Off, .inCallMediaState = CallAssert<>::kAudioSentReceived}});
}

void call() {
	basicCallTemplate(CallTestContext{});
}

void cancelCallUpdate() {
	cancelCallUpdateTemplate(basicCallTemplate(CallTestContext{{.customModuleInjectAfter = "Router"}}));
}

void callWithMultipleDevices() {
	basicCallTemplate(CallTestContext{{.numberOfCallerDevices = 10, .numberOfCalleeDevices = 10}});
}

void callWithMultipleDevicesAndIdleDevices() {
	basicCallTemplate(
	    CallTestContext{{.numberOfCallerDevices = 10, .numberOfCalleeDevices = 5, .numberOfCalleeIdleDevices = 5}});
}

const std::vector<test_t> sTestList{
    CLASSY_TEST(audioOnlyCall),
    CLASSY_TEST(call),
    CLASSY_TEST(cancelCallUpdate),
    CLASSY_TEST(callWithMultipleDevices),
    CLASSY_TEST(callWithMultipleDevicesAndIdleDevices),
};

TestSuite _{
    "Call",
    sTestList,
    Hooks().beforeSuite([] {
	    sServerConfig.insert_or_assign("module::MediaRelay/enabled", "false");
	    return 0;
    }),
};

TestSuite __{
    "CallWithMediaRelay",
    sTestList,
    Hooks().beforeSuite([] {
	    sServerConfig.insert_or_assign("module::MediaRelay/enabled", "true");
	    return 0;
    }),
};

} // namespace
} // namespace flexisip::tester