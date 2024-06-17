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

#include <json/json.h>

#include "linphone++/enums.hh"
#include "linphone/core.h"
#include <bctoolbox/logging.h>
#include <linphone++/linphone.hh>

#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/flexisip-version.h"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"

#include "mediastreamer2/msutils.h"
#include "module-toolbox.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace linphone;
using namespace flexisip;

namespace flexisip {
namespace tester {
namespace b2buatester {
// B2bua is configured to set media encryption according to a regex on the callee URI
// define uri to match each of the possible media encryption
static constexpr auto srtpUri = "sip:b2bua_srtp@sip.example.org";
static constexpr auto zrtpUri = "sip:b2bua_zrtp@sip.example.org";
static constexpr auto dtlsUri = "sip:b2bua_dtlsp@sip.example.org";

static constexpr auto defaultDtlsSrtpSuite = linphone::SrtpSuite::AESCM128HMACSHA180;
static constexpr auto defaultZrtpSrtpSuite = linphone::SrtpSuite::AEADAES128GCM;
static constexpr auto defaultClientSdesSrtpSuite = linphone::SrtpSuite::AEADAES128GCM;
static constexpr auto defaultServerSdesSrtpSuite = linphone::SrtpSuite::AESCM128HMACSHA180;

// Forge an INVITE with an erroneous request address, but appropriate To: header.
// The B2BUA should only use the To: header to build the other leg of the call.
static void trenscrypter__uses_aor_and_not_contact() {
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
	BC_ASSERT_FALSE(unexpected.hasReceivedCallFrom(caller));
}

// Test value of the "User-Agent:" header when a request is routed through the b2bua-server.
static void request_header__user_agent() {
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

// Test value of "user-agent" parameter in b2bua-server.
static void configuration__user_agent() {
	const auto getServerConfig = [](const B2buaAndProxyServer& server) {
		return server.getAgent()->getConfigManager().getRoot()->get<GenericStruct>("b2bua-server");
	};

	// Test exception is thrown when parameter is ill-formed: string is empty.
	{
		B2buaAndProxyServer server{"", false};
		getServerConfig(server)->get<ConfigString>("user-agent")->set("");
		BC_ASSERT_THROWN(server.init(), std::runtime_error);
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
		BC_ASSERT_THROWN(server.init(), std::runtime_error);

		serverConfig->get<ConfigString>("user-agent")->set("name-with-illegal-character-{/{version}");
		BC_ASSERT_THROWN(server.init(), std::runtime_error);
	}

	// Test exception is thrown when parameter is ill-formed: <name>/<wrong_version>.
	{
		B2buaAndProxyServer server{"", false};
		getServerConfig(server)
		    ->get<ConfigString>("user-agent")
		    ->set("1-.!%*_+`'~-test-name/version-with-illegal-character-{");
		BC_ASSERT_THROWN(server.init(), std::runtime_error);
	}
}

// Basic call not using the B2bua server
static void basic() {
	// Create a server and start it
	auto server = make_shared<Server>("config/flexisip_b2bua.conf");
	// flexisip_b2bua config file enables the module B2bua in proxy, disable it for this basic test
	server->getConfigManager()
	    ->getRoot()
	    ->get<GenericStruct>("module::B2bua")
	    ->get<ConfigBoolean>("enabled")
	    ->set("false");
	server->start();

	// create clients and register them on the server
	ClientBuilder builder{*server->getAgent()};
	builder.setVideoSend(OnOff::On);
	auto pauline = builder.build("sip:pauline@sip.example.org");
	auto marie = builder.build("sip:marie@sip.example.org");
	BC_ASSERT_PTR_NOT_NULL(marie.getAccount());

	// marie calls pauline with default call params
	marie.call(pauline);
	pauline.endCurrentCall(marie); // endCurrentCall will fail if there is no current call

	// marie calls pauline with call params
	auto callParams = marie.getCore()->createCallParams(nullptr);
	callParams->setMediaEncryption(linphone::MediaEncryption::ZRTP);
	auto marieCall = marie.call(pauline, callParams);
	if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return; // stop the test if we fail to establish the call
	BC_ASSERT_TRUE(marieCall->getCurrentParams()->getMediaEncryption() == linphone::MediaEncryption::ZRTP);
	BC_ASSERT_TRUE(
	    ClientCall::getLinphoneCall(pauline.getCurrentCall().value())->getCurrentParams()->getMediaEncryption() ==
	    linphone::MediaEncryption::ZRTP);
	marie.endCurrentCall(pauline);

	// marie calls with video pauline with default call params
	// This could also be achieved by setting enableVideo(true) in the callParams given to the call function
	if (!BC_ASSERT_PTR_NOT_NULL(marie.callVideo(pauline))) return;
	pauline.endCurrentCall(marie);
}

/**
 * Scenario: Marie calls Pauline
 * encryptions on outgoing and incoming calls are checked
 * When video is enabled, perform
 * 		- a call with video enabled form start
 * 		. a call audio only updated to add video and then remove it
 *
 * @param[in] marieName			sip URI of user Marie
 * @param[in] marieEncryption	MediaEncryption used for outgoing call
 * @param[in] paulineName		sip URI of user Pauline
 * @param[in] paulineEncryption	MediaEncryption expected for incoming call (not enforced at callee callParams level)
 * @param[in] video				perform video call when true
 * @param[in] marieSrtpSuiteSetting	if not empty, enforce this list in Marie call params
 * @param[in] expectedMarieSuite	if not Invalid, check Marie uses this Srtp suite
 * @param[in] expectedPaulineSuite	if not Invalid, check Pauline uses this Srtp suite
 *
 * @return true when everything went well
 */
static bool mixedEncryption(const std::string& marieName,
                            linphone::MediaEncryption marieEncryption,
                            const std::string& paulineName,
                            linphone::MediaEncryption paulineEncryption,
                            bool video,
                            const std::list<linphone::SrtpSuite>& marieSrtpSuiteSetting = {},
                            const linphone::SrtpSuite expectedMarieSuite = linphone::SrtpSuite::Invalid,
                            const linphone::SrtpSuite expectedPaulineSuite = linphone::SrtpSuite::Invalid) {
	// initialize and start the proxy and B2bua server
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	ClientBuilder builder{*server->getAgent()};
	builder.setVideoSend(OnOff::On);
	// Create and register clients
	auto marie = builder.build(marieName);
	auto pauline = builder.build(paulineName);

	// Marie calls Pauline
	auto marieCallParams = marie.getCore()->createCallParams(nullptr);
	marieCallParams->setMediaEncryption(marieEncryption);
	marieCallParams->enableVideo(video);
	if (!marieSrtpSuiteSetting.empty()) {
		marieCallParams->setSrtpSuites(marieSrtpSuiteSetting);
	}
	auto marieCall = marie.call(pauline, marieCallParams);
	BC_HARD_ASSERT_NOT_NULL(marieCall); // stop the test if we fail to establish the call
	auto marieStats = marie.getCurrentCall()->getStats(linphone::StreamType::Audio);
	auto paulineStats = pauline.getCurrentCall()->getStats(linphone::StreamType::Audio);
	BC_HARD_ASSERT_TRUE(marieStats->getSrtpSource() == marieEncryption);
	BC_HARD_ASSERT_TRUE(paulineStats->getSrtpSource() == paulineEncryption);
	if (expectedMarieSuite != linphone::SrtpSuite::Invalid) {
		BC_HARD_ASSERT_TRUE(marieStats->getSrtpSuite() == expectedMarieSuite);
	}
	if (expectedPaulineSuite != linphone::SrtpSuite::Invalid) {
		BC_HARD_ASSERT_TRUE(paulineStats->getSrtpSuite() == expectedPaulineSuite);
	}
	// we're going through a back-2-back user agent, so the callIds are not the same
	auto paulineCall = ClientCall::getLinphoneCall(pauline.getCurrentCall().value());
	BC_HARD_ASSERT_TRUE(marieCall->getCallLog()->getCallId() != paulineCall->getCallLog()->getCallId());
	BC_HARD_ASSERT_TRUE(marie.endCurrentCall(pauline));

	// updating call to add and remove video
	if (video) {
		auto marieCallParams = marie.getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		// Call audio only
		auto marieCall = marie.call(pauline, marieCallParams);
		BC_HARD_ASSERT_NOT_NULL(marieCall);
		auto paulineCall = ClientCall::getLinphoneCall(pauline.getCurrentCall().value());
		marieStats = marieCall->getStats(linphone::StreamType::Audio);
		paulineStats = paulineCall->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_TRUE(marieStats->getSrtpSource() == marieEncryption);
		BC_HARD_ASSERT_TRUE(paulineStats->getSrtpSource() == paulineEncryption);
		BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
		BC_ASSERT_FALSE(paulineCall->getCurrentParams()->videoEnabled());
		// update call to add video
		marieCallParams->enableVideo(true);
		// The callUpdate checks that video is enabled
		BC_HARD_ASSERT_TRUE(marie.callUpdate(pauline, marieCallParams));
		marieStats = marie.getCurrentCall()->getStats(linphone::StreamType::Audio);
		paulineStats = pauline.getCurrentCall()->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_TRUE(marieStats->getSrtpSource() == marieEncryption);
		BC_HARD_ASSERT_TRUE(paulineStats->getSrtpSource() == paulineEncryption);
		// update call to remove video
		marieCallParams->enableVideo(false);
		// The callUpdate checks that video is disabled
		BC_HARD_ASSERT_TRUE(marie.callUpdate(pauline, marieCallParams));
		marieStats = marie.getCurrentCall()->getStats(linphone::StreamType::Audio);
		paulineStats = pauline.getCurrentCall()->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_TRUE(marieStats->getSrtpSource() == marieEncryption);
		BC_HARD_ASSERT_TRUE(paulineStats->getSrtpSource() == paulineEncryption);
		BC_HARD_ASSERT_TRUE(marie.endCurrentCall(pauline));
	}
	return true;
}

static void forward() {
	// Use uri not matching anything in the b2bua server config, so ougoing media encryption shall match incoming one
	// SDES
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::SRTP, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::SRTP, true));
	// ZRTP
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::ZRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::ZRTP,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::ZRTP, true));
	// DTLS
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::DTLS,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::DTLS,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::DTLS, true));
	// None
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::None,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::None, false));
	BC_ASSERT_TRUE(mixedEncryption("sip:marie@sip.example.org", linphone::MediaEncryption::None,
	                               "sip:pauline@sip.example.org", linphone::MediaEncryption::None, true));
}

static void sdes2zrtp() {
	// sdes to zrtp
	BC_ASSERT_TRUE(mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP,
	                               false, {}, defaultClientSdesSrtpSuite, defaultZrtpSrtpSuite));
	BC_ASSERT_TRUE(mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP,
	                               true, {}, defaultClientSdesSrtpSuite, defaultZrtpSrtpSuite));
	// zrtp to sdes
	BC_ASSERT_TRUE(mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP,
	                               false, {}, defaultZrtpSrtpSuite, defaultServerSdesSrtpSuite));
	BC_ASSERT_TRUE(mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP,
	                               true, {}, defaultZrtpSrtpSuite, defaultServerSdesSrtpSuite));
}

static void sdes2dtls() {
	// sdes to dtls
	BC_ASSERT_TRUE(mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS,
	                               false, {}, defaultClientSdesSrtpSuite, defaultDtlsSrtpSuite));
	BC_ASSERT_TRUE(mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS,
	                               true, {}, defaultClientSdesSrtpSuite, defaultDtlsSrtpSuite));
	// dtls to sdes
	BC_ASSERT_TRUE(mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP,
	                               false, {}, defaultDtlsSrtpSuite, defaultServerSdesSrtpSuite));
	BC_ASSERT_TRUE(mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP,
	                               true, {}, defaultDtlsSrtpSuite, defaultServerSdesSrtpSuite));
}

static void zrtp2dtls() {
	// zrtp to dtls
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, dtlsUri, linphone::MediaEncryption::DTLS, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(zrtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true));
	// dtls to zrtp
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, false));
	BC_ASSERT_TRUE(
	    mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, true));
}

static void sdes2sdes256(bool video) {
	// Call from SDES to SDES256
	BC_ASSERT_TRUE(mixedEncryption("sip:b2bua_srtp@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:b2bua_srtp256@sip.example.org", linphone::MediaEncryption::SRTP, video,
	                               {linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA132},
	                               linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA180));
	// Call from SDES256 to SDES
	BC_ASSERT_TRUE(mixedEncryption("sip:b2bua_srtp256@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:b2bua_srtp@sip.example.org", linphone::MediaEncryption::SRTP, video,
	                               {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132},
	                               linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA180));
	// Call from SDES256 to SDES256gcm
	BC_ASSERT_TRUE(mixedEncryption("sip:b2bua_srtp256@sip.example.org", linphone::MediaEncryption::SRTP,
	                               "sip:b2bua_srtpgcm@sip.example.org", linphone::MediaEncryption::SRTP, video,
	                               {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132},
	                               linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AEADAES256GCM));
}

static void sdes2sdes256() {
	sdes2sdes256(false);
	sdes2sdes256(true);
}

static void disableAllVideoCodecs(std::shared_ptr<linphone::Core> core) {
	auto payloadTypes = core->getVideoPayloadTypes();
	for (const auto& pt : payloadTypes) {
		pt->enable(false);
	}
}

template <const char codec[]>
static void trenscrypter__video_call_with_forced_codec() {
	// initialize and start the proxy and B2bua server
	B2buaAndProxyServer server{"config/flexisip_b2bua.conf"};
	// Create and register clients
	ClientBuilder builder{*server.getAgent()};
	builder.setVideoSend(OnOff::On);
	auto pauline = builder.build("sip:pauline@sip.example.org");
	auto marie = builder.build("sip:marie@sip.example.org");

	// Check we have the requested codec
	auto payloadTypeMarie = marie.getCore()->getPayloadType(codec, LINPHONE_FIND_PAYLOAD_IGNORE_RATE,
	                                                        LINPHONE_FIND_PAYLOAD_IGNORE_CHANNELS);
	auto payloadTypePauline = pauline.getCore()->getPayloadType(codec, LINPHONE_FIND_PAYLOAD_IGNORE_RATE,
	                                                            LINPHONE_FIND_PAYLOAD_IGNORE_CHANNELS);
	if (payloadTypeMarie == nullptr || payloadTypePauline == nullptr) {
		BC_HARD_FAIL(("Video codec not available: "s + codec).c_str());
	}

	// Force usage of the requested codec
	disableAllVideoCodecs(marie.getCore());
	disableAllVideoCodecs(pauline.getCore());
	payloadTypeMarie->enable(true);
	payloadTypePauline->enable(true);

	// Place a video call
	if (!BC_ASSERT_PTR_NOT_NULL(marie.callVideo(pauline))) return;
	pauline.endCurrentCall(marie);
}

static void videoRejected() {
	// initialize and start the proxy and B2bua server
	auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	{
		// Create and register clients
		auto marie = make_shared<CoreClient>("sip:marie@sip.example.org", server->getAgent());
		auto pauline = make_shared<CoreClient>("sip:pauline@sip.example.org", server->getAgent());
		CoreAssert asserter{marie, pauline, server};

		auto marieCallParams = marie->getCore()->createCallParams(nullptr);
		marieCallParams->enableVideo(true);

		// marie call pauline, asking for video
		auto marieCall = marie->invite(*pauline, marieCallParams);

		if (!BC_ASSERT_PTR_NOT_NULL(marieCall)) return;
		if (!BC_ASSERT_TRUE(asserter.wait([pauline] {
			    return ((pauline->getCurrentCall().has_value()) &&
			            (pauline->getCurrentCall()->getState() == linphone::Call::State::IncomingReceived));
		    }))) {
			return;
		}

		auto paulineCall = pauline->getCurrentCall();
		if (!BC_ASSERT_TRUE(paulineCall.has_value())) return;

		if (!BC_ASSERT_TRUE(asserter.wait(
		        [marieCall] { return (marieCall->getState() == linphone::Call::State::OutgoingRinging); }))) {
			return;
		}

		// Callee answer the call but reject video
		auto paulineCallParams = pauline->getCore()->createCallParams(ClientCall::getLinphoneCall(*paulineCall));
		paulineCallParams->enableVideo(false);
		if (!BC_ASSERT_TRUE(ClientCall::getLinphoneCall(*paulineCall)->acceptWithParams(paulineCallParams) == 0))
			return;

		if (!BC_ASSERT_TRUE(asserter.wait([marieCall, paulineCall] {
			    return (marieCall->getState() == linphone::Call::State::StreamsRunning &&
			            paulineCall->getState() == linphone::Call::State::StreamsRunning);
		    }))) {
			return;
		}

		// Check video is disabled on both calls
		BC_ASSERT_FALSE(marieCall->getCurrentParams()->videoEnabled());
		BC_ASSERT_FALSE(ClientCall::getLinphoneCall(*paulineCall)->getCurrentParams()->videoEnabled());

		pauline->endCurrentCall(marie);
	}
}

class FailIfUpdatedByRemote : public CallListener {
public:
	bool passed = true;

private:
	void
	onStateChanged(const std::shared_ptr<linphone::Call>&, linphone::Call::State state, const std::string&) override {
		passed &= BC_ASSERT(state != linphone::Call::State::UpdatedByRemote);
	}
};

/** In an established call, the B2BUA was not behaving properly when a participant attempted to pause the call with
   audio direction "inactive":

   Pauser         B2BUA      Correspondant
     | --INVITE---> |              |
     | a=inactive   |              |
     |              |              |
     |              | --INVITE---> |
     |              | a=sendonly   |
     |              |              |
     |              | <--200 OK--- |
     |              | a=sendonly   |
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
 */
void pauseWithAudioInactive() {
	Server proxy{{
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
	}};
	proxy.start();
	const auto& confMan = proxy.getConfigManager();
	const auto& configRoot = *confMan->getRoot();
	configRoot.get<GenericStruct>("b2bua-server")
	    ->get<ConfigString>("outbound-proxy")
	    ->set("sip:127.0.0.1:" + std::string(proxy.getFirstPort()) + ";transport=tcp");
	const auto& b2bua = make_shared<flexisip::B2buaServer>(proxy.getRoot(), confMan);
	b2bua->init();
	configRoot.get<GenericStruct>("module::B2bua")
	    ->get<ConfigString>("b2bua-server")
	    ->set("sip:127.0.0.1:" + to_string(b2bua->getTcpPort()) + ";transport=tcp");
	proxy.getAgent()->findModule("B2bua")->reload();
	auto builder = ClientBuilder(*proxy.getAgent());
	auto pauser = builder.build("pauser@example.org");
	auto correspondant = builder.build("correspondant@example.org");
	CoreAssert asserter{pauser, proxy, correspondant};
	const auto& pauserCall = pauser.invite(correspondant);
	BC_HARD_ASSERT(pauserCall != nullptr);
	ASSERT_PASSED(correspondant.hasReceivedCallFrom(pauser));
	const auto& correspondantCall = correspondant.getCurrentCall();
	BC_HARD_ASSERT(correspondantCall.has_value());
	correspondantCall->accept();
	asserter
	    .iterateUpTo(
	        8,
	        [&pauserCall]() { return LOOP_ASSERTION(pauserCall->getState() == linphone::Call::State::StreamsRunning); },
	        500ms)
	    .assert_passed();

	const auto& withAudioInactive = pauser.getCore()->createCallParams(pauserCall);
	withAudioInactive->setAudioDirection(linphone::MediaDirection::Inactive);
	pauserCall->update(withAudioInactive);
	asserter
	    .iterateUpTo(
	        8,
	        [&correspondantCall, &pauserCall]() {
		        FAIL_IF(correspondantCall->getState() != linphone::Call::State::PausedByRemote);
		        FAIL_IF(pauserCall->getState() != linphone::Call::State::StreamsRunning);
		        return ASSERTION_PASSED();
	        },
	        500ms)
	    .assert_passed();
	BC_ASSERT_ENUM_EQUAL(correspondantCall->getState(), linphone::Call::State::PausedByRemote);
	BC_ASSERT_ENUM_EQUAL(correspondantCall->getAudioDirection(), linphone::MediaDirection::RecvOnly);
	BC_ASSERT_ENUM_EQUAL(pauserCall->getState(), linphone::Call::State::StreamsRunning);
	BC_ASSERT_ENUM_EQUAL(pauserCall->getCurrentParams()->getAudioDirection(), linphone::MediaDirection::Inactive);

	const auto& reinviteCheck = std::make_shared<FailIfUpdatedByRemote>();
	pauserCall->addListener(reinviteCheck);
	correspondant.endCurrentCall(pauser);
	BC_ASSERT(reinviteCheck->passed);
}

namespace {

/** Test that unknown media attributes are filtered out of tho 200 OK response sent by the B2BUA on reinvites.

    Scenario:
    - Establish a call through the B2BUA
    - Callee sends a re-INVITE with an unknown media attribute
    - The Proxy verifies that the B2BUA accepts the re-INVITE without the custom attribute.
*/
static void unknownMediaAttrAreFilteredOutOnReinvites() {
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

const char VP8[] = "vp8";
// const char H264[] = "h264";

TestSuite _{
    "B2bua",
    {
        CLASSY_TEST(trenscrypter__uses_aor_and_not_contact),
        CLASSY_TEST(request_header__user_agent),
        CLASSY_TEST(configuration__user_agent),
        TEST_NO_TAG("Basic", basic),
        TEST_NO_TAG("Forward Media Encryption", run<forward>),
        TEST_NO_TAG("SDES to ZRTP call", run<sdes2zrtp>),
        TEST_NO_TAG("SDES to DTLS call", run<sdes2dtls>),
        TEST_NO_TAG("ZRTP to DTLS call", run<zrtp2dtls>),
        TEST_NO_TAG("SDES to SDES256 call", run<sdes2sdes256>),
        CLASSY_TEST(trenscrypter__video_call_with_forced_codec<VP8>),
        // H264 is not supported in flexisip sdk's build. So even if the b2bua core is able to
        // relay h264 video without decoding, the test client cannot support it
        // Uncomment when h264 support can be built
        // CLASSY_TEST(trenscrypter__video_call_with_forced_codec<H264>),
        TEST_NO_TAG("Video rejected by callee", videoRejected),
        CLASSY_TEST(pauseWithAudioInactive),
        CLASSY_TEST(unknownMediaAttrAreFilteredOutOnReinvites),
        CLASSY_TEST(forcedAudioCodec),
    },
};
} // namespace
} // namespace b2buatester
} // namespace tester
} // namespace flexisip
