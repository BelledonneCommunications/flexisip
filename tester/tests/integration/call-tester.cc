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
    {"global/transports", "sip:127.0.0.1:0 sip:[::1]:0"},
    {"module::MediaRelay/enabled", "false"},
    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
    {"module::Registrar/enabled", "true"},
    {"module::Registrar/reg-domains", "sip.example.org"},
};

class CallTestContext {
public:
	CallTestContext() = default;
	CallTestContext(const uint numberOfCallerDevices,
	                const uint numberOfCalleeDevices,
	                const std::string& callerUri,
	                const std::string& calleeUri,
	                const OnOff videoCall)
	    : numberOfCallerDevices(numberOfCallerDevices), numberOfCalleeDevices(numberOfCalleeDevices),
	      callerUri(callerUri), calleeUri(calleeUri), videoCall(videoCall) {
	}

	CallTestContext enableVideoCall() {
		this->videoCall = OnOff::On;
		return setInCallMediaState(CallAssert<>::kAllMediaSentReceived);
	}

	CallTestContext setNumberOfCallerDevices(const uint pNumberOfCallerDevices) {
		this->numberOfCallerDevices = pNumberOfCallerDevices;
		return *this;
	}

	CallTestContext setNumberOfCalleeDevices(const uint pNumberOfCalleeDevices) {
		this->numberOfCalleeDevices = pNumberOfCalleeDevices;
		return *this;
	}

	CallTestContext setNumberOfCalleeIdleDevices(const uint pNumberOfCalleeIdleDevices) {
		this->numberOfCalleeIdleDevices = pNumberOfCalleeIdleDevices;
		return *this;
	}

	CallTestContext setInCallMediaState(const CallAssertionInfo::MediaStateList& pInCallMediaState) {
		this->inCallMediaState = pInCallMediaState;
		return *this;
	}

	size_t numberOfCallerDevices = 1;
	size_t numberOfCalleeDevices = 1;
	size_t numberOfCalleeIdleDevices = 1;
	std::string callerUri = "sip:caller@sip.example.org";
	std::string calleeUri = "sip:callee@sip.example.org";
	OnOff videoCall = OnOff::Off;
	CallAssertionInfo::MediaStateList inCallMediaState = CallAssert<>::kAudioSentReceived;
};

void callTestTemplate(const CallTestContext& ctx) {
	// Arrange server
	Server server(sServerConfig);
	server.start();

	// Arrange clients
	ClientBuilder builder{server.getAgent()};
	builder.setVideoReceive(OnOff::On).setVideoSend(OnOff::On);
	vector<CoreClient> callerDevices{};
	for (size_t i = 0; i < ctx.numberOfCallerDevices; i++) {
		callerDevices.push_back(builder.build("sip:caller@sip.example.org;device=n"s + to_string(i)));
	}
	const auto callee = "sip:callee@sip.example.org";
	vector<CoreClient> calleeDevices;
	for (size_t i = 0; i < ctx.numberOfCalleeDevices; i++) {
		calleeDevices.push_back(builder.build(callee + ";device=n"s + to_string(i)));
	}
	vector<CoreClient> calleeIdleDevices;
	for (size_t i = 0; i < ctx.numberOfCalleeIdleDevices; i++) {
		calleeIdleDevices.push_back(builder.build(callee + ";device=idle-n"s + to_string(i)));
	}

	// Arrange asserter
	CoreAssert asserter(server);
	asserter.registerSteppables(callerDevices);
	asserter.registerSteppables(calleeDevices);
	asserter.registerSteppables(calleeIdleDevices);

	// Assert all clients registered without issue
	for (const auto& calleeDevice : calleeDevices) {
		BC_HARD_ASSERT_TRUE(calleeDevice.isRegistered(asserter));
	}
	for (const auto& callerDevice : callerDevices) {
		BC_HARD_ASSERT_TRUE(callerDevice.isRegistered(asserter));
	}
	for (const auto& calleeIdleDevice : calleeIdleDevices) {
		BC_HARD_ASSERT_TRUE(calleeIdleDevice.isRegistered(asserter));
		calleeIdleDevice.disconnect();
	}

	// Actually start the call
	const auto callBuilder = callerDevices.front().callBuilder().setVideo(ctx.videoCall);
	auto callerCall = callBuilder.call(callee);

	// Assert that every callee received the call, choose a device to answer the call
	BC_HARD_ASSERT(callerCall.has_value());
	optional<ClientCall> answeringCall;
	vector<ClientCall> otherDevicesCalls;
	for (const auto& calleeDevice : calleeDevices) {
		BC_HARD_ASSERT_TRUE(calleeDevice.hasReceivedCallFrom(callerDevices.front(), asserter));
		auto calleeCall = calleeDevice.getCurrentCall();
		BC_HARD_ASSERT(calleeCall.has_value());
		if (!answeringCall.has_value()) {
			answeringCall = std::move(calleeCall);
		} else {
			otherDevicesCalls.push_back(std::move(calleeCall.value()));
		}
	}

	// Accept the call
	auto callStatus = answeringCall->accept();
	BC_HARD_ASSERT_CPP_EQUAL(callStatus, 0);

	// Assert the call is running fine
	CallAssert callAsserter{asserter};
	CallAssert<>::CallAssertionInfoList info = {
	    {*callerCall, linphone::Call::State::StreamsRunning, ctx.inCallMediaState},
	    {*answeringCall, linphone::Call::State::StreamsRunning, ctx.inCallMediaState},
	};
	for (const auto& otherDevicesCall : otherDevicesCalls) {
		info.push_back({otherDevicesCall, linphone::Call::State::Released, CallAssert<>::kNoMedia});
	}
	callAsserter.waitUntil(info).hard_assert_passed();
}

void basicCall() {
	callTestTemplate(CallTestContext{});
}

void videoCall() {
	callTestTemplate(CallTestContext{}.enableVideoCall());
}

void videoCallWithMultipleDevices() {
	callTestTemplate(CallTestContext{}.enableVideoCall().setNumberOfCallerDevices(10).setNumberOfCalleeDevices(10));
}

void videoCallWithMultipleDevicesAndIdleDevices() {
	callTestTemplate(CallTestContext{}
	                     .enableVideoCall()
	                     .setNumberOfCallerDevices(10)
	                     .setNumberOfCalleeDevices(5)
	                     .setNumberOfCalleeIdleDevices(5));
}

const std::vector<test_t> sTestList = {
    CLASSY_TEST(basicCall),
    CLASSY_TEST(videoCall),
    CLASSY_TEST(videoCallWithMultipleDevices),
    CLASSY_TEST(videoCallWithMultipleDevicesAndIdleDevices),
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