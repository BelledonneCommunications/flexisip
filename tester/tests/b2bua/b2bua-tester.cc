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

#include "b2bua/b2bua-server.hh"

#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include "linphone++/enums.hh"
#include "linphone++/linphone.hh"

#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"
#include "modules/module-toolbox.hh"
#include "registrardb-internal.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/asserts.hh"
#include "utils/call-assert.hh"
#include "utils/call-listeners.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/custom-user-agent-behavior.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace flexisip;
using namespace linphone;

namespace flexisip::tester::b2buatester {
namespace {

const string PAUSER = "PAUSER";
const string PAUSEE = "PAUSEE";

/**
 * @brief Basic call not using the B2bua server.
 */
void basicCall() {
	// Create a server and start it
	Server server{"config/flexisip_b2bua.conf"};
	// flexisip_b2bua config file enables the module B2bua in proxy, disable it for this basic test
	server.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::B2bua")
	    ->get<ConfigBoolean>("enabled")
	    ->set("false");
	server.start();

	// Create clients and register them on the server
	ClientBuilder builder{*server.getAgent()};
	builder.setVideoSend(OnOff::On);
	auto pauline = builder.build("sip:pauline@sip.example.org");
	auto marie = builder.build("sip:marie@sip.example.org");
	BC_ASSERT_PTR_NOT_NULL(marie.getAccount());

	// Marie calls pauline with default call params.
	marie.call(pauline);
	// Will fail if there is no current call.
	pauline.endCurrentCall(marie);

	// Marie calls pauline with call params.
	const auto callParams = marie.getCore()->createCallParams(nullptr);
	callParams->setMediaEncryption(linphone::MediaEncryption::ZRTP);
	const auto marieCall = marie.call(pauline, callParams);
	BC_HARD_ASSERT(marieCall != nullptr);

	BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::ZRTP);
	BC_ASSERT_ENUM_EQUAL(
	    ClientCall::getLinphoneCall(pauline.getCurrentCall().value())->getCurrentParams()->getMediaEncryption(),
	    linphone::MediaEncryption::ZRTP);
	BC_HARD_ASSERT(marie.endCurrentCall(pauline));

	// Marie calls with video pauline with default call params.
	// This could also be achieved by setting enableVideo(true) in the callParams given to the call function.
	BC_HARD_ASSERT(marie.callVideo(pauline) != nullptr);
	BC_ASSERT(pauline.endCurrentCall(marie));
}

/**
 * @brief Establish a call where the callee first accepts with early media.
 *
 * For each step of the call (acceptWithEarlyMedia and accept): test that both clients are in the right call state and
 * that media is being sent/received on both call legs.
 */
void basicCallWithEarlyMedia() {
	Server proxy{{
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	}};
	proxy.start();

	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	const auto proxyUri = "sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp";
	configRoot.get<GenericStruct>("b2bua-server")->get<ConfigString>("outbound-proxy")->set(proxyUri);

	// Instantiate and start B2BUA server.
	const auto& b2bua = make_shared<B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();

	// Set module::B2bua/b2bua-server parameter value in configuration.
	const auto b2buaUri = "sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp";
	configRoot.get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(b2buaUri);
	proxy.getAgent()->findModuleByRole("B2bua")->reload();

	ClientBuilder builder{*proxy.getAgent()};
	auto caller = builder.build("sip:caller@sip.example.org");
	auto callee = builder.build("sip:callee@sip.example.org");

	CoreAssert asserter{proxy, b2bua, caller, callee};
	CallAssert callAsserter{asserter};

	// Caller invites callee.
	const auto callerCall = ClientCall::tryFrom(caller.invite(callee));
	BC_HARD_ASSERT(callerCall.has_value());
	callee.hasReceivedCallFrom(caller, asserter).hard_assert_passed();

	// Callee accepts with early media.
	const auto calleeCall = callee.getCurrentCall();
	BC_HARD_ASSERT(calleeCall.has_value());
	std::ignore = calleeCall->acceptEarlyMedia();

	callAsserter
	    .waitUntil({
	        {*callerCall, Call::State::OutgoingEarlyMedia, CallAssert<>::kAudioSentReceived},
	        {*calleeCall, Call::State::IncomingEarlyMedia, CallAssert<>::kAudioSentReceived},
	    })
	    .hard_assert_passed();

	// Callee finally accepts the call.
	std::ignore = calleeCall->accept();

	callAsserter
	    .waitUntil({
	        {*callerCall, Call::State::StreamsRunning, CallAssert<>::kAudioSentReceived},
	        {*calleeCall, Call::State::StreamsRunning, CallAssert<>::kAudioSentReceived},
	    })
	    .hard_assert_passed();

	BC_ASSERT(callee.endCurrentCall(caller));

	std::ignore = b2bua->stop();
}

/**
 * @brief Establish a call where the callee declines the call.
 */
void basicCallDeclined() {
	B2buaAndProxyServer B2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	ClientBuilder builder{*B2buaAndProxy.getAgent()};
	auto caller = builder.build("sip:caller@sip.example.org");
	auto callee = builder.build("sip:callee@sip.example.org");

	CoreAssert asserter{B2buaAndProxy, caller, callee};
	CallAssert callAsserter{asserter};

	// Caller invites callee.
	const auto callerCall = ClientCall::tryFrom(caller.invite(callee));
	BC_HARD_ASSERT(callerCall.has_value());
	callee.hasReceivedCallFrom(caller, asserter).hard_assert_passed();

	// Callee declines the call.
	const auto calleeCall = callee.getCurrentCall();
	BC_HARD_ASSERT(calleeCall.has_value());
	std::ignore = calleeCall->decline(Reason::Declined);

	callAsserter.waitUntil({{*callerCall, Call::State::Released}, {*calleeCall, Call::State::Released}})
	    .hard_assert_passed();
}

/**
 * @brief Establish a call where the caller puts the call on hold then resumes it.
 */
template <const OnOff sendRecvAudio, const OnOff sendRecvVideo>
void basicCallOnHoldThenResume() {
	B2buaAndProxyServer B2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"b2bua-server/enable-ice", "false"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	CallAssertionInfo::MediaStateList sentReceivedStatus{};
	if constexpr (sendRecvAudio == OnOff::On) {
		sentReceivedStatus.insert(sentReceivedStatus.end(), CallAssert<>::kAudioSentReceived.begin(),
		                          CallAssert<>::kAudioSentReceived.end());
	}
	if constexpr (sendRecvVideo == OnOff::On) {
		sentReceivedStatus.insert(sentReceivedStatus.end(), CallAssert<>::kVideoSentReceived.begin(),
		                          CallAssert<>::kVideoSentReceived.end());
	}

	ClientBuilder builder{*B2buaAndProxy.getAgent()};
	builder.setVideoSend(sendRecvVideo).setVideoReceive(sendRecvVideo);
	auto caller = builder.build("sip:caller@sip.example.org");
	auto callee = builder.build("sip:callee@sip.example.org");

	CoreAssert asserter{B2buaAndProxy, caller, callee};
	CallAssert callAsserter{asserter};

	const auto callParams = caller.getCore()->createCallParams(nullptr);
	callParams->enableAudio(sendRecvAudio == OnOff::On);
	callParams->enableVideo(sendRecvVideo == OnOff::On);

	// Caller invites callee.
	const auto callerCall = ClientCall::tryFrom(caller.invite(callee, callParams));
	BC_HARD_ASSERT(callerCall.has_value());
	callee.hasReceivedCallFrom(caller, asserter).hard_assert_passed();

	// Callee accepts the call.
	const auto calleeCall = callee.getCurrentCall();
	BC_HARD_ASSERT(calleeCall.has_value());
	std::ignore = calleeCall->accept();

	callAsserter
	    .waitUntil({
	        {*callerCall, Call::State::StreamsRunning, sentReceivedStatus},
	        {*calleeCall, Call::State::StreamsRunning, sentReceivedStatus},
	    })
	    .hard_assert_passed();

	// "Caller" pauses the call.
	std::ignore = callerCall->pause();

	CallAssertionInfo::MediaStateList callerMediaStatus{};
	CallAssertionInfo::MediaStateList calleeMediaStatus{};
	// Only verify that call participants are not receiving (pauser) or sending (pausee) data.
	if constexpr (sendRecvAudio == OnOff::On) {
		// callerMediaStatus.emplace_back(StreamType::Audio, MediaAssertionStatus::NotReceived);
		calleeMediaStatus.emplace_back(StreamType::Audio, CallAssertionInfo::MediaState::NotSent);
	}
	// WARNING: Linphone UACs stop sending the video from the webcam but send a static image "no webcam"
	// instead, at 1fps. Thus, upload (pauser) and download (pausee) bandwidth are much lower.
	if constexpr (sendRecvVideo == OnOff::On) {
		callerMediaStatus.emplace_back(StreamType::Video, CallAssertionInfo::MediaState::NotReceived);
		calleeMediaStatus.emplace_back(StreamType::Video, CallAssertionInfo::MediaState::NotSent);
	}
	callAsserter
	    .waitUntil({
	        {*callerCall, Call::State::Paused, callerMediaStatus},
	        {*calleeCall, Call::State::PausedByRemote, calleeMediaStatus},
	    })
	    .hard_assert_passed();

	// "Caller" resumes the call.
	std::ignore = callerCall->resume();

	callAsserter
	    .waitUntil({
	        {*callerCall, Call::State::StreamsRunning, sentReceivedStatus},
	        {*calleeCall, Call::State::StreamsRunning, sentReceivedStatus},
	    })
	    .hard_assert_passed();

	BC_ASSERT(callee.endCurrentCall(caller));
}

/**
 * @brief Forge an INVITE request with an erroneous request address, but appropriate "To:" header. The B2BUA should only
 * use the "To:" header to build the other leg of the call.
 */
void usesAORButNotContact() {
	const auto unexpectedRecipient = "sip:unexpected@sip.example.org";
	SipUri injectedRequestUrl{unexpectedRecipient};
	InjectedHooks hooks{
	    .onRequest =
	        [&injectedRequestUrl](std::unique_ptr<RequestSipEvent>&& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, flexisip::B2buaServer::kCustomHeader)) {
			        return std::move(responseEvent);
		        }

		        // Mangle the request address
		        sip->sip_request->rq_url[0] = *injectedRequestUrl.get();
		        return std::move(responseEvent);
	        },
	};
	B2buaAndProxyServer server{"config/flexisip_b2bua.conf", true, &hooks};
	ClientBuilder builder{*server.getAgent()};
	auto caller = builder.build("sip:caller@sip.example.org");
	auto unexpected = builder.build(unexpectedRecipient);
	const auto intendedRecipient = "sip:intended@sip.example.org";
	auto intended = builder.build(intendedRecipient);

	auto call = caller.invite(intendedRecipient);

	CoreAssert asserter{server, caller, intended};
	intended.hasReceivedCallFrom(caller, asserter).assert_passed();
	BC_ASSERT(!unexpected.hasReceivedCallFrom(caller, asserter));
}

/**
 * @brief Test value of the "User-Agent:" header when a request is routed through the b2bua-server.
 */
void userAgentHeader() {
	constexpr auto expected{"test-user-agent-value/stub-version"};
	constexpr auto unexpected{"unexpected-user-agent-value"};
	std::string userAgentValue{unexpected};

	InjectedHooks hooks{
	    .onRequest =
	        [&userAgentValue](std::unique_ptr<RequestSipEvent>&& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, flexisip::B2buaServer::kCustomHeader) == nullptr) {
			        return std::move(responseEvent);
		        }

		        userAgentValue = sip_user_agent(sip)->g_string;
		        return std::move(responseEvent);
	        },
	};
	B2buaAndProxyServer server{"config/flexisip_b2bua.conf", false, &hooks};
	server.getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("user-agent")
	    ->set(expected);
	server.start();

	const auto caller = ClientBuilder(*server.getAgent()).build("sip:caller@sip.example.org");
	CoreAssert asserter{caller, server};

	caller.invite("sip:recipient@sip.example.org");

	asserter
	    .iterateUpTo(
	        4,
	        [&userAgentValue]() {
		        FAIL_IF(userAgentValue == unexpected);
		        return ASSERTION_PASSED();
	        },
	        1s)
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(userAgentValue, expected);
}

/**
 * @brief Test value of "user-agent" parameter in b2bua-server.
 */
void userAgentParameterConfiguration() {
	const auto getServerConfig = [](const B2buaAndProxyServer& b2bua) {
		return b2bua.getAgent()->getConfigManager().getRoot()->get<GenericStruct>("b2bua-server");
	};

	// Test exception is thrown when parameter is ill-formed: string is empty.
	{
		B2buaAndProxyServer b2bua{"", false};
		getServerConfig(b2bua)->get<ConfigString>("user-agent")->set("");
		BC_ASSERT_THROWN(b2bua.startB2bua(), BadConfiguration);
	}

	// Test when value is well-formed: <name>.
	{
		B2buaAndProxyServer b2bua{"", false};
		const auto expected = ".!%*_+`'~-12-Hello-";
		getServerConfig(b2bua)->get<ConfigString>("user-agent")->set(expected);

		b2bua.startB2bua();

		BC_ASSERT_CPP_EQUAL(b2bua.getCore()->getUserAgent(), expected);
	}

	// Test when value is well-formed: <name>/<version>.
	{
		B2buaAndProxyServer b2bua{"", false};
		const auto expected = "1-.!%*_+`'~-test-name/test_version-.!%*_+`'~";
		getServerConfig(b2bua)->get<ConfigString>("user-agent")->set(expected);

		b2bua.startB2bua();

		BC_ASSERT_CPP_EQUAL(b2bua.getCore()->getUserAgent(), expected);
	}

	// Test when value is well-formed: <name>/{version}.
	{
		B2buaAndProxyServer b2bua{"", false};
		const auto expected = "a-test-.!%*_+`'~/";
		getServerConfig(b2bua)->get<ConfigString>("user-agent")->set(expected + string("{version}"));

		b2bua.startB2bua();

		BC_ASSERT_CPP_EQUAL(b2bua.getCore()->getUserAgent(), expected + string(FLEXISIP_GIT_VERSION));
	}

	// Test exception is thrown when parameter is ill-formed: <wrong_name>/<version>|{version}.
	{
		B2buaAndProxyServer b2bua{"", false};
		const auto b2buaConfig = getServerConfig(b2bua);
		b2buaConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/.!%*_+`'~-0-Test-version");
		BC_ASSERT_THROWN(b2bua.startB2bua(), BadConfiguration);

		b2buaConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/{version}");
		BC_ASSERT_THROWN(b2bua.startB2bua(), BadConfiguration);
	}

	// Test exception is thrown when parameter is ill-formed: <name>/<wrong_version>.
	{
		B2buaAndProxyServer b2bua{"", false};
		getServerConfig(b2bua)
		    ->get<ConfigString>("user-agent")
		    ->set("1-.!%*_+`'~-test-name/version-with-illegal-character-{");
		BC_ASSERT_THROWN(b2bua.startB2bua(), BadConfiguration);
	}
}

void videoRejectedByCallee() {
	// Initialize and start the proxy and B2bua server
	B2buaAndProxyServer server{"config/flexisip_b2bua.conf"};
	// Create and register clients.
	ClientBuilder builder{*server.getAgent()};
	auto marie = builder.build("sip:marie@sip.example.org");
	auto pauline = builder.build("sip:pauline@sip.example.org");
	CoreAssert asserter{marie, pauline, server};

	auto marieCallParams = marie.getCore()->createCallParams(nullptr);
	marieCallParams->enableVideo(true);

	// Marie call pauline, asking for video.
	auto marieCall = marie.invite(pauline, marieCallParams);
	BC_HARD_ASSERT(marieCall != nullptr);
	asserter
	    .wait([&pauline] {
		    const auto paulineCall = pauline.getCurrentCall();
		    FAIL_IF(!paulineCall);
		    FAIL_IF(paulineCall->getState() != linphone::Call::State::IncomingReceived);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	const auto paulineCall = pauline.getCurrentCall();
	asserter.wait([&marieCall] { return (marieCall->getState() == linphone::Call::State::OutgoingRinging); })
	    .hard_assert_passed();

	// Callee answer the call but reject video.
	auto paulineCallParams = pauline.getCore()->createCallParams(ClientCall::getLinphoneCall(*paulineCall));
	paulineCallParams->enableVideo(false);
	BC_HARD_ASSERT(ClientCall::getLinphoneCall(*paulineCall)->acceptWithParams(paulineCallParams) == 0);
	asserter
	    .wait([&marieCall, &paulineCall] {
		    FAIL_IF(marieCall->getState() != linphone::Call::State::StreamsRunning);
		    FAIL_IF(paulineCall->getState() != linphone::Call::State::StreamsRunning);
		    return ASSERTION_PASSED();
	    })
	    .hard_assert_passed();

	// Check video is disabled on both calls.
	BC_ASSERT(!marieCall->getCurrentParams()->videoEnabled());
	BC_ASSERT(!ClientCall::getLinphoneCall(*paulineCall)->getCurrentParams()->videoEnabled());
	BC_HARD_ASSERT(pauline.endCurrentCall(marie));
}

class FailIfUpdatedByRemote : public linphone::CallListener {
public:
	bool passed = true;

private:
	void
	onStateChanged(const std::shared_ptr<linphone::Call>&, linphone::Call::State state, const std::string&) override {
		passed &= BC_ASSERT(state != linphone::Call::State::UpdatedByRemote);
	}
};

/** In an established call, the B2BUA was not behaving properly when the pauser attempted to pause the call with audio
    direction "inactive":

   Pauser         B2BUA          Pausee
     | --INVITE---> |              |
     | a=inactive   |              |
     |              |              |
     |              | --INVITE---> |
     |              | a=sendonly   |
     |              |              |
     |              | <--200 OK--- |
     |              | a=recvonly   |
     |              |              |
     | <--200 OK--- |              |
     | a=inactive   |              |
     |              |              |
     | <x-INVITE-x- |              |
     | a=inactive   |              |

    This test checks that this last erroneous re-INVITE does not happen.

   We get everything up to the point where Pauser's INVITE is accepted (so, right before the erroneous re-INVITE on the
   part of the B2BUA), then set up a trigger on Pauser's call to fail on re-INVITEs, and let the calls terminate on
   their own.

   TODO: refactor pause tests to remove code duplication.
 */
void pauseWithAudioInactive() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	configRoot.get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:" + string(proxy.getFirstPort()) + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot.get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModuleByRole("B2bua")->reload();

	// Instantiate clients and create call.
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.setInactiveAudioOnPause(OnOff::On).build("pauser@example.org");
	auto pausee = builder.setInactiveAudioOnPause(OnOff::Off).build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	ASSERT_PASSED(pausee.hasReceivedCallFrom(pauser, asserter));
	const auto& pauserCall = pauser.getCurrentCall();
	const auto& pauseeCall = pausee.getCurrentCall();
	BC_HARD_ASSERT(pauseeCall.has_value());
	pauseeCall->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCall]() { return LOOP_ASSERTION(pauserCall->getState() == linphone::Call::State::StreamsRunning); },
	        500ms)
	    .assert_passed();

	// Pause call with a=inactive in SDP (initiated from Pauser).
	callFromPauser->pause();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauseeCall, &pauserCall]() {
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauseeCall->getState() != linphone::Call::State::PausedByRemote);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Check both clients are in the right call state.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getState(), linphone::Call::State::Paused);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getState(), linphone::Call::State::PausedByRemote);
	// Check both clients have the right media direction.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getAudioDirection(), linphone::MediaDirection::Inactive);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getAudioDirection(), linphone::MediaDirection::RecvOnly);

	const auto& reinviteCheck = make_shared<FailIfUpdatedByRemote>();
	callFromPauser->addListener(reinviteCheck);
	pauseeCall->terminate();
	BC_ASSERT(reinviteCheck->passed);
}

/** In an established call, the B2BUA was not behaving properly when the pausee attempted to answer to the pause with
   audio direction "inactive":

   Pauser         B2BUA          Pausee
     | --INVITE---> |              |
     | a=sendonly   |              |
     |              |              |
     |              | --INVITE---> |
     |              | a=sendonly   |
     |              |              |
     |              | <--200 OK--- |
     |              | a=inactive   |
     |              |              |
     | <--200 OK--- |              |
     | a=recvonly   |              |
     |              |              |
     | <x-INVITE-x- |              |
     | a=sendonly   |              |

    This test checks that this last erroneous re-INVITE does not happen.

    TODO: refactor pause tests to remove code duplication.
 */
void answerToPauseWithAudioInactive() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // B2bua use writable-dir instead of var folder
	    {"b2bua-server/data-directory", bcTesterWriteDir()},
	}};
	proxy.start();

	// Instantiate and start B2BUA server.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	configRoot.get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:" + string(proxy.getFirstPort()) + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot.get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModuleByRole("B2bua")->reload();

	// Instantiate clients and create call.
	ClientBuilder builder{*proxy.getAgent()};
	auto pauser = builder.setInactiveAudioOnPause(OnOff::Off).build("pauser@example.org");
	auto pausee = builder.setInactiveAudioOnPause(OnOff::On).build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	ASSERT_PASSED(pausee.hasReceivedCallFrom(pauser, asserter));
	const auto& pauserCall = pauser.getCurrentCall();
	const auto& pauseeCall = pausee.getCurrentCall();
	BC_HARD_ASSERT(pauseeCall.has_value());
	pauseeCall->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCall]() { return LOOP_ASSERTION(pauserCall->getState() == linphone::Call::State::StreamsRunning); },
	        500ms)
	    .assert_passed();

	// Pause call with a=sendonly in SDP. Pausee will answer to pause with a=inactive.
	callFromPauser->pause();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauseeCall, &pauserCall]() {
		        FAIL_IF(pauseeCall->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::Paused);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Check both clients are in the right call state.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getState(), linphone::Call::State::Paused);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getState(), linphone::Call::State::PausedByRemote);
	// Check both clients have the right media direction.
	BC_ASSERT_ENUM_EQUAL(pauserCall->getAudioDirection(), linphone::MediaDirection::SendOnly);
	BC_ASSERT_ENUM_EQUAL(pauseeCall->getAudioDirection(), linphone::MediaDirection::Inactive);

	const auto& reinviteCheck = make_shared<FailIfUpdatedByRemote>();
	callFromPauser->addListener(reinviteCheck);
	pauseeCall->terminate();
	BC_ASSERT(reinviteCheck->passed);
}

/*
 * Test that a bridged call that has been put on hold on both call legs correctly terminates once one of the call leg
 * terminates the call.
 */
template <const string& legThatInitiatesCallEnd>
void terminateCallPausedOnBothSides() {
	B2buaAndProxyServer b2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	// Instantiate clients.
	const auto builder = ClientBuilder(*b2buaAndProxy.getAgent());
	auto pauser = builder.build("pauser@sip.example.org");
	auto pausee = builder.build("pausee@sip.example.org");

	// Create call.
	CoreAssert asserter{b2buaAndProxy, pauser, pausee};
	const auto pauserCallToPausee = ClientCall::tryFrom(pauser.invite(pausee));
	pausee.hasReceivedCallFrom(pauser, asserter).hard_assert_passed();

	// Accept call.
	const auto pauseeCallFromPauser = pausee.getCurrentCall();
	pauseeCallFromPauser->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(pauserCallToPausee->getAudioDirection() != linphone::MediaDirection::SendRecv);

		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Pause call from "Pauser".
	pauserCallToPausee->pause();

	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauserCallToPausee->getAudioDirection() != linphone::MediaDirection::SendOnly);

		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::RecvOnly);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Pause call from "Pausee".
	pauseeCallFromPauser->pause();

	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauserCallToPausee->getAudioDirection() != linphone::MediaDirection::Inactive);

		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::Inactive);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Terminate call.
	if (legThatInitiatesCallEnd == PAUSER) pauserCallToPausee->terminate();
	else pauseeCallFromPauser->terminate();

	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::Released);
		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();
}

/*
 * Test that a bridged call that has been put on hold on both call legs correctly resumes once one of the call leg
 * resumes the call.
 */
template <const string& legThatInitiatedResume, OnOff pauseeAnswersWithAudioInactive>
void resumeCallPausedOnBothSides() {
	B2buaAndProxyServer b2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	// Instantiate clients.
	ClientBuilder builder{*b2buaAndProxy.getAgent()};
	auto pauser = builder.build("pauser@sip.example.org");
	auto pausee = builder.setInactiveAudioOnPause(pauseeAnswersWithAudioInactive).build("pausee@sip.example.org");

	// Make our "Pausee" client behave as the well-known server of the Jabiru project.
	if (pauseeAnswersWithAudioInactive == OnOff::On) pausee.addListener(make_shared<JabiruServerBehavior>());

	// Create call.
	CoreAssert asserter{b2buaAndProxy, pauser, pausee};
	const auto pauserCallToPausee = ClientCall::tryFrom(pauser.invite(pausee));
	pausee.hasReceivedCallFrom(pauser, asserter).hard_assert_passed();

	// Accept call.
	const auto pauseeCallFromPauser = pausee.getCurrentCall();
	pauseeCallFromPauser->accept();

	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(pauserCallToPausee->getAudioDirection() != linphone::MediaDirection::SendRecv);

		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Pause call from "Pauser".
	pauserCallToPausee->pause();

	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauserCallToPausee->getAudioDirection() != linphone::MediaDirection::SendOnly);

		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::PausedByRemote);
		        if (pauseeAnswersWithAudioInactive == OnOff::On) {
			        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::Inactive);
		        } else {
			        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::RecvOnly);
		        }
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	// Pause call from "Pausee".
	pauseeCallFromPauser->pause();

	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCallToPausee, &pauseeCallFromPauser]() {
		        FAIL_IF(pauserCallToPausee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauserCallToPausee->getAudioDirection() != linphone::MediaDirection::Inactive);

		        FAIL_IF(pauseeCallFromPauser->getState() != linphone::Call::State::Paused);
		        FAIL_IF(pauseeCallFromPauser->getAudioDirection() != linphone::MediaDirection::Inactive);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();

	const auto& resumerCall = (legThatInitiatedResume == PAUSER ? pauserCallToPausee : pauseeCallFromPauser);
	const auto& resumeeCall = (legThatInitiatedResume == PAUSER ? pauseeCallFromPauser : pauserCallToPausee);

	// Resume call from "Resumer".
	resumerCall->resume();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&resumerCall, &resumeeCall]() {
		        FAIL_IF(resumerCall->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(resumerCall->getAudioDirection() != linphone::MediaDirection::RecvOnly);

		        FAIL_IF(resumeeCall->getState() != linphone::Call::State::Paused);
		        if (pauseeAnswersWithAudioInactive == OnOff::On and legThatInitiatedResume == PAUSER) {
			        FAIL_IF(resumeeCall->getAudioDirection() != linphone::MediaDirection::Inactive);
		        } else {
			        FAIL_IF(resumeeCall->getAudioDirection() != linphone::MediaDirection::SendOnly);
		        }
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// Resume call from "Resumee".
	resumeeCall->resume();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&resumerCall, &resumeeCall]() {
		        FAIL_IF(resumerCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(resumerCall->getAudioDirection() != linphone::MediaDirection::SendRecv);

		        FAIL_IF(resumeeCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(resumeeCall->getAudioDirection() != linphone::MediaDirection::SendRecv);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

/** Test that unknown media attributes are filtered out of tho 200 OK response sent by the B2BUA on reinvites.

    Scenario:
    - Establish a call through the B2BUA
    - Callee sends a re-INVITE with an unknown media attribute
    - The Proxy verifies that the B2BUA accepts the re-INVITE without the custom attribute.
*/
void unknownMediaAttrAreFilteredOutOnReinvites() {
	static const auto& mediaAttribute = "filtered-out-custom-media-attribute"s;
	constexpr auto findMediaAttribute = [](auto& result) {
		return [&result](auto&& event) {
			const auto* sip = event->getSip();
			if (sip->sip_cseq->cs_method != sip_method_invite) return std::move(event);
			if (sip->sip_from->a_url->url_user != "reinviter"sv) return std::move(event);

			const auto* const payload = sip->sip_payload;
			if (!payload) return std::move(event);

			const auto notFound =
			    string_view(payload->pl_data, payload->pl_len).find(mediaAttribute) == string_view::npos;
			result = notFound ? "not found" : "found";
			return std::move(event);
		};
	};
	auto customAttrInRequest = "hook did not trigger"sv;
	auto customAttrInResponse = "hook did not trigger"sv;
	auto hooks = InjectedHooks{
	    .onRequest = findMediaAttribute(customAttrInRequest),
	    .onResponse = findMediaAttribute(customAttrInResponse),
	};
	auto proxy = Server{
	    {
	        // Requesting bind on port 0 to let the kernel find any available port
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	        {"b2bua-server/application", "trenscrypter"},
	        // Forward everything to the b2bua
	        {"module::B2bua/enabled", "true"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "example.org"},
	        // Media Relay has problem when everyone is running on localhost
	        {"module::MediaRelay/enabled", "false"},
	        // B2bua use writable-dir instead of var folder
	        {"b2bua-server/data-directory", bcTesterWriteDir()},
	    },
	    &hooks,
	};
	proxy.start();
	const auto& confMan = proxy.getConfigManager();
	const auto* const configRoot = confMan->getRoot();
	configRoot->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModuleByRole("B2bua")->reload();
	const auto& builder = ClientBuilder(*proxy.getAgent());
	const auto& caller = builder.build("sip:caller@example.org");
	const auto& reinviter = builder.build("sip:reinviter@example.org");
	auto asserter = CoreAssert{caller, proxy, reinviter};
	caller.invite(reinviter);
	ASSERT_PASSED(reinviter.hasReceivedCallFrom(caller, asserter));
	const auto& reinviterCall = reinviter.getCurrentCall();
	BC_HARD_ASSERT(reinviterCall.has_value());
	reinviterCall->accept();
	BC_ASSERT_ENUM_EQUAL(reinviterCall->getState(), linphone::Call::State::StreamsRunning);

	reinviterCall->update([](auto&& reinviteParams) {
		reinviteParams->addCustomSdpMediaAttribute(linphone::StreamType::Audio, mediaAttribute, "");
		return std::move(reinviteParams);
	});

	BC_ASSERT_ENUM_EQUAL(reinviterCall->getState(), linphone::Call::State::Updating);
	ASSERT_PASSED(asserter.iterateUpTo(
	    2,
	    [&reinviterCall]() {
		    return LOOP_ASSERTION(reinviterCall->getState() == linphone::Call::State::StreamsRunning);
	    },
	    150ms));
	BC_ASSERT_CPP_EQUAL(customAttrInRequest, "found");
	BC_ASSERT_CPP_EQUAL(customAttrInResponse, "not found");
}

/** Test that configuring an "audio-codec" in the "b2bua-server" section will force all calls -- incoming *and* outgoing
   -- to use that codec.

    Setup a bridged call between two clients that support multiple codecs, assert that both legs have negotiated the
   configured codec
 */
void forcedAudioCodec() {
	auto proxy = Server{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "example.org"},
	    // Media Relay has problem when everyone is running on localhost
	    {"module::MediaRelay/enabled", "false"},
	    // Forward everything to the b2bua
	    {"module::B2bua/enabled", "true"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"b2bua-server/audio-codec", "speex/8000"},
	}};
	proxy.start();
	const auto& confMan = proxy.getConfigManager();
	const auto* const configRoot = confMan->getRoot();
	configRoot->get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot->get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModuleByRole("B2bua")->reload();
	auto builder = ClientBuilder(*proxy.getAgent());
	auto caller = builder.build("sip:caller@example.org");
	const auto& callee = builder.build("sip:callee@example.org");
	BC_HARD_ASSERT(1 < caller.getCore()->getAudioPayloadTypes().size());
	BC_HARD_ASSERT(1 < callee.getCore()->getAudioPayloadTypes().size());

	const auto& callerCall = caller.call(callee);
	BC_HARD_ASSERT(callerCall != nullptr);

	const auto& legACodec = callerCall->getCurrentParams()->getUsedAudioPayloadType();
	BC_ASSERT_CPP_EQUAL(legACodec->getMimeType(), "speex");
	BC_ASSERT_CPP_EQUAL(legACodec->getClockRate(), 8000);
	const auto& legBCodec = callee.getCurrentCall()->getAudioPayloadType();
	BC_ASSERT_CPP_EQUAL(legBCodec->getMimeType(), "speex");
	BC_ASSERT_CPP_EQUAL(legBCodec->getClockRate(), 8000);
}

/*
 * Test successful blind call transfer.
 * This test implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-7
 *
 * Architecture:
 * - One Proxy server (sip.example.org)
 * - One B2BUA server
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} registered on sip.example.org.
 */
void blindCallTransferSuccessful() {
	B2buaAndProxyServer B2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	// Instantiate clients.
	auto builder = ClientBuilder{*B2buaAndProxy.getAgent()};
	auto transferor = builder.build("transferor@sip.example.org");
	auto transferee = builder.build("transferee@sip.example.org");
	auto transferTarget = builder.build("transferTarget@sip.example.org");

	CoreAssert asserter{B2buaAndProxy, transferor, transferee, transferTarget};

	// Create call from "Transferee" to "Transferor".
	const auto transferorAOR = transferor.getMe()->asStringUriOnly();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAOR));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Attach a call listener to "Transferor's" call in order to verify receipt of NOTIFY requests.
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);

	// Transfer call to "TransferTarget", initiated by "Transferor".
	transferorCallFromTransferee->transferTo(transferTarget.getMe()->clone());
	transferTarget.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	const auto transferTargetCallFromTransferee = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferee.has_value());

	// Verify that call between "Transferee" and "Transferor" is paused while waiting for "TransferTarget" answer.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::OutgoingRinging);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::IncomingReceived);
		        // Verify "Transferor" received NOTIFY 100 Trying.
		        FAIL_IF(transferListener->mLastState != linphone::Call::State::OutgoingProgress);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify content of "Referred-By" header.
	const SipUri referredByAddress{transferTargetCallFromTransferee->getReferredByAddress()->asStringUriOnly()};
	const SipUri transferorAddress{transferorAOR};
	BC_ASSERT(referredByAddress.compareAll(transferorAddress));

	// Accept call from "Transferee" to "TransferTarget".
	transferTargetCallFromTransferee->accept();

	// Verify "Transferor" received NOTIFY 200 Ok.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Connected).assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Released);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	BC_ASSERT(transferTarget.endCurrentCall(transferee));
}

/*
 * Test blind call transfer when "TransferTarget" declines the call.
 * This test almost implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-10
 *
 * Architecture:
 * - One Proxy server (sip.example.org)
 * - One B2BUA server
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} registered on sip.example.org.
 */
void blindCallTransferDeclined() {
	B2buaAndProxyServer B2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	// Instantiate clients.
	auto builder = ClientBuilder{*B2buaAndProxy.getAgent()};
	auto transferor = builder.build("transferor@sip.example.org");
	auto transferee = builder.build("transferee@sip.example.org");
	auto transferTarget = builder.build("transferTarget@sip.example.org");

	CoreAssert asserter{B2buaAndProxy, transferor, transferee, transferTarget};

	// Create call from "Transferee" to "Transferor".
	const auto transferorAOR = transferor.getMe()->asStringUriOnly();
	const auto transfereeCallToTransferor = ClientCall ::tryFrom(transferee.invite(transferorAOR));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Attach a call listener to "Transferor's" call in order to verify receipt of NOTIFY requtests.
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);

	// Transfer call to "TransferTarget", initiated by "Transferor".
	transferorCallFromTransferee->transferTo(transferTarget.getMe()->clone());
	transferTarget.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	const auto transferTargetCallFromTransferee = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferee.has_value());

	// Verify that call between "Transferee" and "Transferor" is paused while waiting for "TransferTarget" answer.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::OutgoingRinging);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::IncomingReceived);
		        // Verify "Transferor" received NOTIFY 100 Trying.
		        FAIL_IF(transferListener->mLastState != linphone::Call::State::OutgoingProgress);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify content of "Referred-By" header.
	const SipUri referredByAddress{transferTargetCallFromTransferee->getReferredByAddress()->asStringUriOnly()};
	const SipUri transferorAddress{transferorAOR};
	BC_ASSERT(referredByAddress.compareAll(transferorAddress));

	// Decline call from "Transferee" to "TransferTarget".
	transferTargetCallFromTransferee->decline(linphone::Reason::Declined);

	// Verify "Transferor" received NOTIFY 500 Internal Server Error.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Error).assert_passed();

	// Resume call after failed call transfer.
	transfereeCallToTransferor->resume();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	BC_ASSERT(transferee.endCurrentCall(transferor));
}

/*
 * Test successful attended call transfer.
 * This test almost implements the following scenario: https://datatracker.ietf.org/doc/html/rfc5589#autoid-15
 *
 * Architecture:
 * - One Proxy server (sip.example.org)
 * - One B2BUA server
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} registered on sip.example.org.
 */
void attendedCallTransferSuccessful() {
	B2buaAndProxyServer B2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	// Instantiate clients.
	auto builder = ClientBuilder{*B2buaAndProxy.getAgent()};
	auto transferor = builder.build("transferor@sip.example.org");
	auto transferee = builder.build("transferee@sip.example.org");
	auto transferTarget = builder.build("transferTarget@sip.example.org");

	CoreAssert asserter{B2buaAndProxy, transferor, transferee, transferTarget};

	// Create call from "Transferee" to "Transferor".
	const auto transferorAOR = transferor.getMe()->asStringUriOnly();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAOR));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Create call from "Transferor" to "TransferTarget".
	const auto transferorCallToTransferTarget = ClientCall::tryFrom(transferor.invite(transferTarget));
	transferTarget.hasReceivedCallFrom(transferor, asserter).hard_assert_passed();

	// Accept call from transferor.
	const auto transferTargetCallFromTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferor.has_value());
	transferTargetCallFromTransferor->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call between "Transferee" and "Transferor" to call between "Transferor" and "TransferTarget".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	transferorCallFromTransferee->transferToAnother(*transferorCallToTransferTarget);

	// Verify "TransferTarget" received a call from "Transferee" and accept it.
	optional<ClientCall> transferTargetCallFromTransferee{};
	asserter
	    .iterateUpTo(
	        0x20,
	        [&, &targetCore = *transferTarget.getCore(), transfereeUser = transferee.getMe()->getUsername()]() {
		        for (auto&& call : targetCore.getCalls()) {
			        if (call->getRemoteAddress()->getUsername() == transfereeUser) {
				        transferTargetCallFromTransferee = ClientCall::tryFrom(std::move(call));
				        transferTargetCallFromTransferee->accept();
				        return ASSERTION_PASSED();
			        }
		        }

		        return ASSERTION_FAILED("Transfer target has not received any call from transferee");
	        },
	        2s)
	    .hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	BC_ASSERT_CPP_EQUAL(transfereeCallToTransferTarget->getRemoteAddress()->getUsername(),
	                    transferTarget.getMe()->getUsername());

	// Verify "Transferor" received NOTIFY 200 Ok.
	transferListener->assertNotifyReceived(asserter, linphone::Call::State::Connected).assert_passed();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Released);

		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::Released);

		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

/*
 * Test attended call transfer when "TransferTarget" declines the call.
 *
 * Architecture:
 * - One Proxy server (sip.example.org)
 * - One B2BUA server
 * - Three clients {"Transferee", "Transferor", "TransferTarget"} registered on sip.example.org.
 */
void attendedCallTransferDeclined() {
	B2buaAndProxyServer B2buaAndProxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::B2bua/enabled", "true"},
	    {"module::MediaRelay/enabled", "false"},
	}};

	// Instantiate clients.
	auto builder = ClientBuilder{*B2buaAndProxy.getAgent()};
	builder.setAutoAnswerReplacingCalls(OnOff::Off);
	auto transferor = builder.build("transferor@sip.example.org");
	auto transferee = builder.build("transferee@sip.example.org");
	auto transferTarget = builder.build("transferTarget@sip.example.org");

	CoreAssert asserter{B2buaAndProxy, transferor, transferee, transferTarget};

	// Create call from "Transferee" to "Transferor".
	const auto transferorAOR = transferor.getMe()->asStringUriOnly();
	const auto transfereeCallToTransferor = ClientCall::tryFrom(transferee.invite(transferorAOR));
	BC_HARD_ASSERT(transfereeCallToTransferor.has_value());
	transferor.hasReceivedCallFrom(transferee, asserter).hard_assert_passed();

	// Accept call from "Transferee".
	const auto transferorCallFromTransferee = transferor.getCurrentCall();
	BC_HARD_ASSERT(transferorCallFromTransferee.has_value());
	transferorCallFromTransferee->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Create call from "Transferor" to "TransferTarget".
	const auto transferorCallToTransferTarget = ClientCall::tryFrom(transferor.invite(transferTarget));
	BC_HARD_ASSERT(transferorCallToTransferTarget.has_value());
	transferTarget.hasReceivedCallFrom(transferor, asserter).hard_assert_passed();

	// Accept call from transferor.
	const auto transferTargetCallFromTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallFromTransferor.has_value());
	transferTargetCallFromTransferor->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call between "Transferee" and "Transferor" to call between "Transferor" and "TransferTarget".
	const auto transferListener = make_shared<CallTransferListener>();
	transferorCallFromTransferee->addListener(transferListener);
	transferorCallFromTransferee->transferToAnother(*transferorCallToTransferTarget);

	// Verify "TransferTarget" received a call from "Transferee" and decline it.
	auto transferTargetCallFromTransferee = optional<ClientCall>();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&, &targetCore = *transferTarget.getCore(), transfereeUser = transferee.getMe()->getUsername()]() {
		        for (auto&& call : targetCore.getCalls()) {
			        if (call->getRemoteAddress()->getUsername() == transfereeUser) {
				        transferTargetCallFromTransferee = ClientCall::tryFrom(std::move(call));
				        transferTargetCallFromTransferee->decline(linphone::Reason::Declined);
				        return ASSERTION_PASSED();
			        }
		        }

		        return ASSERTION_FAILED("Transfer target has not received any call from transferee");
	        },
	        2s)
	    .hard_assert_passed();

	const auto transfereeCallToTransferTarget = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallToTransferTarget.has_value());
	BC_ASSERT_CPP_EQUAL(transfereeCallToTransferTarget->getRemoteAddress()->getUsername(),
	                    transferTarget.getMe()->getUsername());

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        // Verify "Transferor" received NOTIFY 500 Internal Server Error.
		        FAIL_IF(transferListener->mLastState != linphone::Call::State::Error);

		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferee->getState() != linphone::Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// "TransferTarget" terminates its call with "Transferor".
	transferTargetCallFromTransferor->terminate();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallToTransferTarget->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCallFromTransferor->getState() != linphone::Call::State::Released);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// "Transferor" resumes its call with "Transferee".
	transferorCallFromTransferee->resume();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::PausedByRemote);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// "Transferee" resumes its call with "Transferor".
	transfereeCallToTransferor->resume();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transfereeCallToTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferorCallFromTransferee->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

/**
 * Test parameter "b2bua-server/transport" and its interaction with "b2bua-server/one-connection-per-account".
 * The "b2bua-server/one-connection-per-account" parameter should not be influenced by "b2bua-server/transport".
 *
 * Expected behavior of the server:
 *   1. When parameter "b2bua-server/one-connection-per-account=false"
 *     - If "b2bua-server/transport" sets a specific transport protocol, the server should still be able to create
 *       outgoing connections on all the other transport protocols.
 *     - In case "transport=TCP", source ports of outgoing connections should be random for all transports.
 *     - In case "transport=UDP", the source port of outgoing connections should be the same as the one the server is
 *       listening on. However, if a message is not sent through UDP, source ports of outgoing connections should be
 *       different random ports.
 *   2. When parameter "b2bua-server/one-connection-per-account=true"
 *     - All outgoing connections should be done on different random ports independently of the selected transport in
 *     parameter "b2bua-server/transport".
 */
template <const string& incomingTransport, const string& outgoingTransport, const bool oneConnectionPerAccount>
void transportAndOneConnectionPerAccount() {
	using namespace sofiasip;
	TmpDir directory{"B2bua::"s + __func__};
	const auto& b2buaConfigPath = directory.path() / "b2bua.conf";
	const auto& providersConfigPath = directory.path() / "providers.json";

	ofstream{b2buaConfigPath} << "[b2bua-server]\n"
	                          << "application=sip-bridge\n"
	                          << "transport=sip:127.0.0.1:0;transport=" << incomingTransport << '\n'
	                          << "one-connection-per-account=" << boolalpha << oneConnectionPerAccount << '\n'
	                          << "data-directory=" << bcTesterWriteDir().string() << '\n'
	                          << "[b2bua-server::sip-bridge]\n"
	                          << "providers=" << providersConfigPath.string();

	StringFormatter providersConfig{
	    R"json({
		"schemaVersion": 2,
		"providers": [],
		"accountPools": {
			"accounts": {
				"outboundProxy": "<sip:127.0.0.2:#externalProxyPort#;transport=#externalProxyTransport#>",
				"registrationRequired": true,
				"maxCallsPerLine": 10,
				"loader": [
					{"uri": "sip:user-1@external.example.org"},
					{"uri": "sip:user-2@external.example.org"}
				]
			}
		}
	})json",
	    '#',
	    '#',
	};

	unordered_set<basic_string<char>> registerPorts{}, unregisterPorts{};

	auto hooks = InjectedHooks{.onRequest = [&registerPorts, &unregisterPorts](auto&& request) {
		const auto* sip = request->getSip();
		if (sip->sip_request->rq_method != sip_method_register) return std::move(request);
		SipUri uri(sip->sip_contact->m_url);

		// For unREGISTER requests the "Expires" header is set to 0
		if (sip->sip_expires->ex_delta == 0) {
			unregisterPorts.emplace(uri.getPort());
		} else {
			registerPorts.emplace(uri.getPort());
		}

		return std::move(request);
	}};

	Server externalProxy{
	    {
	        {"global/transports", "sip:127.0.0.2:0"},
	        {"module::DoSProtection/enabled", "false"},
	        {"module::Registrar/enabled", "true"},
	        {"module::Registrar/reg-domains", "external.example.org"},
	        {"module::MediaRelay/enabled", "false"},
	    },
	    &hooks,
	};
	externalProxy.start();
	ofstream{providersConfigPath} << providersConfig.format({
	    {"externalProxyPort", externalProxy.getFirstPort()},
	    {"externalProxyTransport", outgoingTransport},
	});

	const auto suRoot = make_shared<SuRoot>();
	const auto config = make_shared<ConfigManager>();
	config->load(b2buaConfigPath);

	// Instantiate B2BUA server.
	const auto b2buaServer = make_shared<flexisip::B2buaServer>(suRoot, config);
	b2buaServer->init();
	const auto b2buaTcpPort = to_string(b2buaServer->getTcpPort());
	const auto b2buaUdpPort = to_string(b2buaServer->getUdpPort());
	const auto b2buaPort = incomingTransport == "tcp" ? b2buaTcpPort : b2buaUdpPort;
	const auto b2buaServerUri = "sip:127.0.0.1:" + b2buaPort + ";transport=" + incomingTransport;

	CoreAssert asserter{suRoot, externalProxy};
	const auto& db = dynamic_cast<const RegistrarDbInternal&>(externalProxy.getRegistrarDb()->getRegistrarBackend());
	const auto& registeredUsers = db.getAllRecords();
	asserter.iterateUpTo(
	            3, [&registeredUsers] { return LOOP_ASSERTION(registeredUsers.size() == 2); }, 40ms)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);
	for (const auto& record : registeredUsers) {
		const auto& contacts = record.second->getExtendedContacts();
		BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
		const SipUri uri{contacts.begin()->get()->mSipContact->m_url};
		BC_ASSERT_CPP_EQUAL(uri.getParam("transport"), (outgoingTransport == "udp" ? "" : outgoingTransport));
	}

	auto checkPorts = [&b2buaUdpPort, &b2buaTcpPort](const auto& ports) -> AssertionResult {
		// Test ports of (B2BUA) registered users on external proxy.
		const auto& portUsed1 = *ports.begin();
		if constexpr (oneConnectionPerAccount) {
			// TODO: fix non-working case (UDP-UDP), parameter one-connection-per-account does not have any effect.
			if (incomingTransport == "udp" and outgoingTransport == "udp") {
				FAIL_IF(ports.size() != 1);
				FAIL_IF(portUsed1 != b2buaUdpPort);
			} else {
				FAIL_IF(ports.size() != 2);
				const auto& portUsed2 = *(ports.begin()++);

				FAIL_IF(portUsed1 == b2buaUdpPort);
				FAIL_IF(portUsed2 == b2buaUdpPort);

				FAIL_IF(portUsed2 == b2buaTcpPort);
			}

			FAIL_IF(portUsed1 == b2buaTcpPort);
		} else {
			FAIL_IF(ports.size() != 1);

			if (incomingTransport == "udp" and outgoingTransport == "udp") {
				FAIL_IF(portUsed1 != b2buaUdpPort);
			} else {
				FAIL_IF(portUsed1 == b2buaTcpPort);
				FAIL_IF(portUsed1 == b2buaUdpPort);
			}
		}
		return ASSERTION_PASSED();
	};
	BC_HARD_ASSERT(checkPorts(registerPorts).assert_passed());

	// Test connection with the B2BUA server.
	NtaAgent client{suRoot, "sip:user-1@127.0.0.1:0;transport=" + incomingTransport};
	const auto clientUri = "<sip:user-1@127.0.0.1:"s + client.getFirstPort() + ";transport=" + incomingTransport + ">";
	MsgSip msg{};
	msg.makeAndInsert<SipHeaderRequest>(sip_method_options, "sip:user-2@flexisip.example.org");
	msg.makeAndInsert<SipHeaderFrom>("sip:user-1@flexisip.example.org", "stub-from-tag");
	msg.makeAndInsert<SipHeaderTo>("sip:user-2@flexisip.example.org");
	msg.makeAndInsert<SipHeaderCallID>("stub-call-id");
	msg.makeAndInsert<SipHeaderCSeq>(20u, sip_method_options);
	msg.makeAndInsert<SipHeaderContact>(clientUri);

	const auto transaction = client.createOutgoingTransaction(msg.msgAsString(), b2buaServerUri);
	asserter
	    .iterateUpTo(
	        0x20,
	        [&transaction]() { return LOOP_ASSERTION(transaction->isCompleted() and transaction->getStatus() == 200); },
	        100ms)
	    .assert_passed();

	// Check that the B2BUA send unREGISTER message with the right ports when stopping
	const auto& asyncCleanup = b2buaServer->stop();

	constexpr static auto timeout = 500ms;
	// As of 2024-03-27 and SDK 5.3.33, the SDK goes on a busy loop to wait for accounts to unregister, instead of
	// waiting for iterate to be called again. That blocks the iteration of the proxy, so we spawn a separate cleanup
	// thread to be able to keep iterating the proxy on the main thread (sofia aborts if we attempt to step the main
	// loop on a non-main thread). See SDK-136.
	const auto& cleanupThread = std::async(std::launch::async, [&asyncCleanup = *asyncCleanup]() {
		BcAssert()
		    .iterateUpTo(
		        1, [&asyncCleanup]() { return LOOP_ASSERTION(asyncCleanup.finished()); }, timeout)
		    .assert_passed();
	});
	CoreAssert(externalProxy)
	    .iterateUpTo(
	        10, [&registeredUsers] { return LOOP_ASSERTION(registeredUsers.empty()); }, timeout)
	    .assert_passed();
	externalProxy.getRoot()->step(1ms);

	// Join proxy iterate thread. Leave ample time to let the asserter time-out first.
	cleanupThread.wait_for(10s);

	BC_ASSERT_CPP_EQUAL(registeredUsers.size(), 0);
	BC_HARD_ASSERT(checkPorts(unregisterPorts).assert_passed());
}

const string UDP = "udp";
const string TCP = "tcp";

TestSuite _{
    "b2bua",
    {
        CLASSY_TEST(basicCall),
        CLASSY_TEST(basicCallWithEarlyMedia),
        CLASSY_TEST(basicCallDeclined),

        // Resume test execution once the associated bug has been fixed.
        CLASSY_TEST((basicCallOnHoldThenResume<OnOff::On, OnOff::Off>)).tag("skip"),
        CLASSY_TEST((basicCallOnHoldThenResume<OnOff::On, OnOff::On>)).tag("skip"),
        CLASSY_TEST((basicCallOnHoldThenResume<OnOff::Off, OnOff::On>)).tag("skip"),

        CLASSY_TEST(usesAORButNotContact),
        CLASSY_TEST(userAgentHeader),
        CLASSY_TEST(userAgentParameterConfiguration),
        CLASSY_TEST(videoRejectedByCallee),
        CLASSY_TEST(pauseWithAudioInactive),
        CLASSY_TEST(answerToPauseWithAudioInactive),
        CLASSY_TEST(terminateCallPausedOnBothSides<PAUSER>),
        CLASSY_TEST(terminateCallPausedOnBothSides<PAUSEE>),
        CLASSY_TEST((resumeCallPausedOnBothSides<PAUSER, OnOff::On>)),
        CLASSY_TEST((resumeCallPausedOnBothSides<PAUSER, OnOff::Off>)),
        CLASSY_TEST((resumeCallPausedOnBothSides<PAUSEE, OnOff::On>)),
        CLASSY_TEST((resumeCallPausedOnBothSides<PAUSEE, OnOff::Off>)),
        CLASSY_TEST(unknownMediaAttrAreFilteredOutOnReinvites),
        CLASSY_TEST(forcedAudioCodec),
        CLASSY_TEST(blindCallTransferSuccessful),
        CLASSY_TEST(blindCallTransferDeclined),
        CLASSY_TEST(attendedCallTransferSuccessful),
        CLASSY_TEST(attendedCallTransferDeclined),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, TCP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, TCP, true>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, UDP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<TCP, UDP, true>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, TCP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, TCP, true>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, UDP, false>)),
        CLASSY_TEST((transportAndOneConnectionPerAccount<UDP, UDP, true>)),
    },
};

} // namespace
} // namespace flexisip::tester::b2buatester