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
#include <linphone++/linphone.hh>

#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/sofia-wrapper/sip-header.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"

#include "module-toolbox.hh"
#include "registrardb-internal.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace flexisip;

namespace flexisip::tester::b2buatester {
namespace {

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

	// Set b2bua-server/outbound parameter value in configuration.
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	const auto proxyUri = "sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp";
	configRoot.get<GenericStruct>("b2bua-server")->get<ConfigString>("outbound-proxy")->set(proxyUri);

	// Instantiate and start B2BUA server.
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();

	// Set module::B2bua/b2bua-server parameter value in configuration.
	const auto b2buaUri = "sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp";
	configRoot.get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(b2buaUri);
	proxy.getAgent()->findModule("B2bua")->reload();

	ClientBuilder builder{*proxy.getAgent()};
	auto caller = builder.build("sip:caller@sip.example.org");
	auto callee = builder.build("sip:callee@sip.example.org");

	// Caller invites callee.
	const auto callerCall = caller.invite(callee);
	callee.hasReceivedCallFrom(caller).hard_assert_passed();

	// Callee accepts with early media.
	const auto calleeCall = callee.getCurrentCall();
	calleeCall->acceptEarlyMedia();

	CoreAssert asserter{proxy, b2bua, caller, callee};
	asserter
	    .iterateUpTo(
	        0x20,
	        [&callerCall, &calleeCall]() {
		        FAIL_IF(callerCall->getState() != linphone::Call::State::OutgoingEarlyMedia);
		        FAIL_IF(calleeCall->getState() != linphone::Call::State::IncomingEarlyMedia);

		        const auto callerAudioStats = callerCall->getAudioStats();
		        FAIL_IF(callerAudioStats == nullptr);
		        const auto calleeAudioStats = calleeCall->getAudioStats();
		        FAIL_IF(calleeAudioStats == nullptr);

		        FAIL_IF(callerAudioStats->getDownloadBandwidth() < 10 || callerAudioStats->getUploadBandwidth() < 10);
		        FAIL_IF(calleeAudioStats->getDownloadBandwidth() < 10 || calleeAudioStats->getUploadBandwidth() < 10);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// Callee finally accepts call.
	calleeCall->accept();

	asserter
	    .iterateUpTo(
	        0x20,
	        [&callerCall, &calleeCall]() {
		        FAIL_IF(callerCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(calleeCall->getState() != linphone::Call::State::StreamsRunning);

		        const auto callerAudioStats = callerCall->getAudioStats();
		        FAIL_IF(callerAudioStats == nullptr);
		        const auto calleeAudioStats = calleeCall->getAudioStats();
		        FAIL_IF(calleeAudioStats == nullptr);

		        FAIL_IF(callerAudioStats->getDownloadBandwidth() < 10 || callerAudioStats->getUploadBandwidth() < 10);
		        FAIL_IF(calleeAudioStats->getDownloadBandwidth() < 10 || calleeAudioStats->getUploadBandwidth() < 10);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	BC_ASSERT(callee.endCurrentCall(caller));

	std::ignore = b2bua->stop();
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
	        [&injectedRequestUrl](const std::shared_ptr<RequestSipEvent>& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, flexisip::B2buaServer::kCustomHeader)) {
			        return;
		        }

		        // Mangle the request address
		        sip->sip_request->rq_url[0] = *injectedRequestUrl.get();
	        },
	};
	B2buaAndProxyServer server{"config/flexisip_b2bua.conf", true, &hooks};
	ClientBuilder builder{*server.getAgent()};
	auto caller = builder.build("sip:caller@sip.example.org");
	auto unexpected = builder.build(unexpectedRecipient);
	const auto intendedRecipient = "sip:intended@sip.example.org";
	auto intended = builder.build(intendedRecipient);

	auto call = caller.invite(intendedRecipient);

	intended.hasReceivedCallFrom(caller).assert_passed();
	BC_ASSERT(!unexpected.hasReceivedCallFrom(caller));
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
	        [&userAgentValue](const std::shared_ptr<RequestSipEvent>& responseEvent) {
		        const auto* sip = responseEvent->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite ||
		            ModuleToolbox::getCustomHeaderByName(sip, flexisip::B2buaServer::kCustomHeader) == nullptr) {
			        return;
		        }

		        userAgentValue = sip_user_agent(sip)->g_string;
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
	const auto getServerConfig = [](const B2buaAndProxyServer& server) {
		return server.getAgent()->getConfigManager().getRoot()->get<GenericStruct>("b2bua-server");
	};

	// Test exception is thrown when parameter is ill-formed: string is empty.
	{
		B2buaAndProxyServer server{"", false};
		getServerConfig(server)->get<ConfigString>("user-agent")->set("");
		BC_ASSERT_THROWN(server.init(), FlexisipException);
	}

	// Test when value is well-formed: <name>.
	{
		B2buaAndProxyServer server{"", false};
		const auto expected = ".!%*_+`'~-12-Hello-";
		getServerConfig(server)->get<ConfigString>("user-agent")->set(expected);

		server.init();

		BC_ASSERT_CPP_EQUAL(server.getCore()->getUserAgent(), expected);
	}

	// Test when value is well-formed: <name>/<version>.
	{
		B2buaAndProxyServer server{"", false};
		const auto expected = "1-.!%*_+`'~-test-name/test_version-.!%*_+`'~";
		getServerConfig(server)->get<ConfigString>("user-agent")->set(expected);

		server.init();

		BC_ASSERT_CPP_EQUAL(server.getCore()->getUserAgent(), expected);
	}

	// Test when value is well-formed: <name>/{version}.
	{
		B2buaAndProxyServer server{"", false};
		const auto expected = "a-test-.!%*_+`'~/";
		getServerConfig(server)->get<ConfigString>("user-agent")->set(expected + string("{version}"));

		server.init();

		BC_ASSERT_CPP_EQUAL(server.getCore()->getUserAgent(), expected + string(FLEXISIP_GIT_VERSION));
	}

	// Test exception is thrown when parameter is ill-formed: <wrong_name>/<version>|{version}.
	{
		B2buaAndProxyServer server{"", false};
		const auto serverConfig = getServerConfig(server);
		serverConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/.!%*_+`'~-0-Test-version");
		BC_ASSERT_THROWN(server.init(), FlexisipException);

		serverConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/{version}");
		BC_ASSERT_THROWN(server.init(), FlexisipException);
	}

	// Test exception is thrown when parameter is ill-formed: <name>/<wrong_version>.
	{
		B2buaAndProxyServer server{"", false};
		getServerConfig(server)
		    ->get<ConfigString>("user-agent")
		    ->set("1-.!%*_+`'~-test-name/version-with-illegal-character-{");
		BC_ASSERT_THROWN(server.init(), FlexisipException);
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
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients and create call.
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.setInactiveAudioOnPause(OnOff::On).build("pauser@example.org");
	auto pausee = builder.setInactiveAudioOnPause(OnOff::Off).build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	ASSERT_PASSED(pausee.hasReceivedCallFrom(pauser));
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
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients and create call.
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.setInactiveAudioOnPause(OnOff::Off).build("pauser@example.org");
	auto pausee = builder.setInactiveAudioOnPause(OnOff::On).build("pausee@example.org");
	CoreAssert asserter{pauser, proxy, pausee};
	const auto& callFromPauser = pauser.invite(pausee);
	BC_HARD_ASSERT(callFromPauser != nullptr);
	ASSERT_PASSED(pausee.hasReceivedCallFrom(pauser));
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

/** Test that unknown media attributes are filtered out of tho 200 OK response sent by the B2BUA on reinvites.

    Scenario:
    - Establish a call through the B2BUA
    - Callee sends a re-INVITE with an unknown media attribute
    - The Proxy verifies that the B2BUA accepts the re-INVITE without the custom attribute.
*/
void unknownMediaAttrAreFilteredOutOnReinvites() {
	static const auto& mediaAttribute = "filtered-out-custom-media-attribute"s;
	constexpr auto findMediaAttribute = [](auto& result) {
		return [&result](const auto& event) {
			const auto* sip = event->getSip();
			if (sip->sip_cseq->cs_method != sip_method_invite) return;
			if (sip->sip_from->a_url->url_user != "reinviter"sv) return;

			const auto* const payload = sip->sip_payload;
			if (!payload) return;

			const auto notFound =
			    string_view(payload->pl_data, payload->pl_len).find(mediaAttribute) == string_view::npos;
			result = notFound ? "not found" : "found";
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
	proxy.getAgent()->findModule("B2bua")->reload();
	const auto& builder = ClientBuilder(*proxy.getAgent());
	const auto& caller = builder.build("sip:caller@example.org");
	const auto& reinviter = builder.build("sip:reinviter@example.org");
	auto asserter = CoreAssert{caller, proxy, reinviter};
	caller.invite(reinviter);
	ASSERT_PASSED(reinviter.hasReceivedCallFrom(caller));
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
	proxy.getAgent()->findModule("B2bua")->reload();
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
 * Test blind call transfer.
 *
 * As of 2024-08-23, this test mostly verifies the B2BUA-server does not crash when a REFER request is received.
 *
 * Scenario:
 * 1. A call is established through the B2BUA between "transferor" and "transferee".
 * 2. Transferor transfers its call with transferee to the transfer target "transfer-t".
 * 3. The call between transferor et transferee should be paused until transfer-t answers (pick up or decline) to the
 *    INVITE it received from transferee.
 * 4. Finally, when transfer-t answers, the call should run between transferee and transfer-t. The call between
 *    transferor and transferee is released as soon as NOTIFY/200 OK was received by transferor.
 * ...
 * TODO: correct this test and description once the feature is developed.
 */
void blindCallTransfer() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
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
	const auto proxyUri = "sip:127.0.0.1:" + string{proxy.getFirstPort()} + ";transport=tcp";
	configRoot.get<GenericStruct>("b2bua-server")->get<ConfigString>("outbound-proxy")->set(proxyUri);
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	const auto b2buaUri = "sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp";
	configRoot.get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(b2buaUri);
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients.
	auto builder = ClientBuilder{*proxy.getAgent()};
	auto transferor = builder.build("transferor@example.org");
	auto transferee = builder.build("transferee@example.org");
	auto transferTarget = builder.build("transfer-t@example.org");
	// The B2BUA-server uses the same sofia-loop as the proxy.
	CoreAssert asserter{proxy, transferor, transferee, transferTarget};

	// Create call.
	const auto& callFromTransferor = transferor.invite(transferee);
	BC_HARD_ASSERT(callFromTransferor != nullptr);
	transferee.hasReceivedCallFrom(transferor).hard_assert_passed();
	const auto& transferorCall = transferor.getCurrentCall();
	const auto& transfereeCall = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCall.has_value());

	// Accept call from transferor.
	transfereeCall->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call to transfer target.
	callFromTransferor->transferTo(transferTarget.getAccount()->getContactAddress());
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCall->getState() != linphone::Call::State::PausedByRemote);
		        // As of 2024-08-23, transferee does not receive the REFER request, so it does not send an INVITE
		        // request to transfer-t.
		        // FAIL_IF(transfereeCall->getState() != linphone::Call::State::OutgoingRinging);
		        FAIL_IF(transfereeCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Verify transfer-t received a call and answer to it.
	transferTarget.hasReceivedCallFrom(transferee).hard_assert_passed();
	const auto& transferTargetCall = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCall.has_value());
	transferTargetCall->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCall->getState() != linphone::Call::State::Released);
		        // As of 2024-08-23, transferee does not establish a call with transfer-t and the call gets released
		        // because transferor answered BYE after receiving NOTIFY/200 OK.
		        // FAIL_IF(transfereeCall->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCall->getState() != linphone::Call::State::Released);
		        FAIL_IF(transferTargetCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// As of 2024-08-23, transfer-t has a call with b2bua and not transferee.
	// BC_ASSERT(transferTarget.endCurrentCall(transferee));
	transferTargetCall->terminate();

	std::ignore = b2bua->stop();
}

/*
 * Test attended call transfer.
 *
 * As of 2024-08-23, this test mostly verifies the B2BUA-server does not crash when a REFER request is received.
 *
 * Scenario:
 * 1. A call is established through the B2BUA between "transferor" and "transferee".
 * 2. Another call is established through the B2BUA between "transferor" and "transfer-t".
 * 3. Transferor transfers its call with transferee to the transfer target "transfer-t".
 * ...
 * TODO: finish test once the feature is developed.
 */
void attendedCallTransfer() {
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/transport", "sip:127.0.0.1:0;transport=tcp"},
	    {"b2bua-server/application", "trenscrypter"},
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
	const auto proxyUri = "sip:127.0.0.1:" + string{proxy.getFirstPort()} + ";transport=tcp";
	configRoot.get<GenericStruct>("b2bua-server")->get<ConfigString>("outbound-proxy")->set(proxyUri);
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	const auto b2buaUri = "sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp";
	configRoot.get<GenericStruct>("module::B2bua")->get<ConfigString>("b2bua-server")->set(b2buaUri);
	proxy.getAgent()->findModule("B2bua")->reload();

	// Instantiate clients.
	auto builder = ClientBuilder{*proxy.getAgent()};
	auto transferor = builder.build("transferor@example.org");
	auto transferee = builder.build("transferee@example.org");
	auto transferTarget = builder.build("transfer-t@example.org");
	// The B2BUA-server uses the same sofia-loop as the proxy.
	CoreAssert asserter{proxy, transferor, transferee, transferTarget};

	// Create call from transferor to transferee.
	const auto& callFromTransferorToTransferee = transferor.invite(transferee);
	BC_HARD_ASSERT(callFromTransferorToTransferee != nullptr);
	transferee.hasReceivedCallFrom(transferor).hard_assert_passed();
	const auto& transferorCallWithTransferee = transferor.getCurrentCall();
	const auto& transfereeCallWithTransferor = transferee.getCurrentCall();
	BC_HARD_ASSERT(transfereeCallWithTransferor.has_value());

	// Accept call from transferor to transferee.
	transfereeCallWithTransferor->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallWithTransferee->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCallWithTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Create call from transferor to transfer-t.
	const auto& callFromTransferorToTransferTarget = transferor.invite(transferTarget);
	BC_HARD_ASSERT(callFromTransferorToTransferTarget != nullptr);
	transferTarget.hasReceivedCallFrom(transferor).hard_assert_passed();
	const auto& transferorCallWithTransferTarget = transferor.getCurrentCall();
	const auto& transferTargetCallWithTransferor = transferTarget.getCurrentCall();
	BC_HARD_ASSERT(transferTargetCallWithTransferor.has_value());

	// Accept call from transferor to transfer-t.
	transferTargetCallWithTransferor->accept();
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallWithTransferTarget->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transferTargetCallWithTransferor->getState() != linphone::Call::State::StreamsRunning);
		        FAIL_IF(transfereeCallWithTransferor->getState() != linphone::Call::State::PausedByRemote);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Transfer call to transfer target.
	// As of 2024-08-23, the B2BUA reacts badly to REFER requests (invites himself to a new call).
	callFromTransferorToTransferTarget->transferToAnother(callFromTransferorToTransferee);
	asserter
	    .iterateUpTo(
	        0x20,
	        [&]() {
		        FAIL_IF(transferorCallWithTransferee->getState() != linphone::Call::State::Paused);
		        FAIL_IF(transfereeCallWithTransferor->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferorCallWithTransferTarget->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(transferTargetCallWithTransferor->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// TODO: verify the call between transferee and transfer-t is established.
	// TODO: verify the call between transferor and transferee is released.

	std::ignore = b2bua->stop();
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
	TmpDir directory{string{"B2bua::"s + __func__}.c_str()};
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

	Server externalProxy{{
	    {"global/transports", "sip:127.0.0.2:0"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "external.example.org"},
	    {"module::MediaRelay/enabled", "false"},
	}};
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
	asserter
	    .iterateUpTo(
	        3, [&registeredUsers] { return LOOP_ASSERTION(registeredUsers.size() == 2); }, 40ms)
	    .assert_passed();

	BC_HARD_ASSERT_CPP_EQUAL(registeredUsers.size(), 2);
	auto portsUsed = unordered_set<string>();
	for (const auto& record : registeredUsers) {
		const auto& contacts = record.second->getExtendedContacts();
		BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
		const SipUri uri{contacts.begin()->get()->mSipContact->m_url};
		BC_ASSERT_CPP_EQUAL(uri.getParam("transport"), (outgoingTransport == "udp" ? "" : outgoingTransport));
		portsUsed.emplace(uri.getPort());
	}

	// Test ports of (B2BUA) registered users on external proxy.
	const auto& portUsed1 = *portsUsed.begin();
	if constexpr (oneConnectionPerAccount) {

		// TODO: fix non-working case (UDP-UDP), parameter one-connection-per-account does not have any effect.
		if (incomingTransport == "udp" and outgoingTransport == "udp") {
			BC_ASSERT_CPP_EQUAL(portsUsed.size(), 1);
			BC_ASSERT_CPP_EQUAL(portUsed1, b2buaUdpPort);
		} else {
			BC_HARD_ASSERT_CPP_EQUAL(portsUsed.size(), 2);
			const auto& portUsed2 = *(portsUsed.begin()++);

			BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaUdpPort);
			BC_ASSERT_CPP_NOT_EQUAL(portUsed2, b2buaUdpPort);

			BC_ASSERT_CPP_NOT_EQUAL(portUsed2, b2buaTcpPort);
		}

		BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaTcpPort);
	} else {
		BC_ASSERT_CPP_EQUAL(portsUsed.size(), 1);

		if (incomingTransport == "udp" and outgoingTransport == "udp") {
			BC_ASSERT_CPP_EQUAL(portUsed1, b2buaUdpPort);
		} else {
			BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaTcpPort);
			BC_ASSERT_CPP_NOT_EQUAL(portUsed1, b2buaUdpPort);
		}
	}

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
}

const string UDP = "udp";
const string TCP = "tcp";

TestSuite _{
    "b2bua",
    {
        CLASSY_TEST(basicCall),
        CLASSY_TEST(basicCallWithEarlyMedia),
        CLASSY_TEST(usesAORButNotContact),
        CLASSY_TEST(userAgentHeader),
        CLASSY_TEST(userAgentParameterConfiguration),
        CLASSY_TEST(videoRejectedByCallee),
        CLASSY_TEST(pauseWithAudioInactive),
        CLASSY_TEST(answerToPauseWithAudioInactive),
        CLASSY_TEST(unknownMediaAttrAreFilteredOutOnReinvites),
        CLASSY_TEST(forcedAudioCodec),
        CLASSY_TEST(blindCallTransfer),
        CLASSY_TEST(attendedCallTransfer),
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