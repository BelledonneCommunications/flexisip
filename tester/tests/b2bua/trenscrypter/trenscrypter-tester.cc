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

#include <memory>
#include <sstream>
#include <string>

#include "linphone++/enums.hh"
#include "linphone/core.h"
#include <linphone++/linphone.hh>

#include "flexisip/flexisip-version.h"

#include "module-toolbox.hh"
#include "utils/asserts.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/server/b2bua-and-proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace flexisip;

namespace flexisip::tester::b2buatester {
namespace {

// B2bua is configured to set media encryption according to a regex on the callee URI.
// Define uri to match each of the possible media encryption.
constexpr auto srtpUri = "sip:b2bua_srtp@sip.example.org";
constexpr auto srtp256Uri = "sip:b2bua_srtp256@sip.example.org";
constexpr auto zrtpUri = "sip:b2bua_zrtp@sip.example.org";
constexpr auto dtlsUri = "sip:b2bua_dtlsp@sip.example.org";

constexpr auto defaultDtlsSrtpSuite = linphone::SrtpSuite::AESCM128HMACSHA180;
constexpr auto defaultZrtpSrtpSuite = linphone::SrtpSuite::AEADAES128GCM;
constexpr auto defaultClientSdesSrtpSuite = linphone::SrtpSuite::AEADAES128GCM;
constexpr auto defaultServerSdesSrtpSuite = linphone::SrtpSuite::AESCM128HMACSHA180;

/**
 * @brief Scenario: Marie calls Pauline, encryption on outgoing and incoming calls are verified.
 * When video is enabled, perform:
 * 		- a call with audio and video enabled form start
 * 		- an audio call updated to add video and then remove it
 *
 * @param[in] marieName			     sip URI of user Marie
 * @param[in] marieEncryption	     MediaEncryption used for outgoing call
 * @param[in] paulineName		     sip URI of user Pauline
 * @param[in] paulineEncryption	     MediaEncryption expected for incoming call (not enforced in callee callParams)
 * @param[in] video				     perform video call when true
 * @param[in] marieSrtpSuiteSetting	 if not empty, enforce this list in Marie call params
 * @param[in] expectedMarieSuite	 if not Invalid, check Marie uses this SRTP suite
 * @param[in] expectedPaulineSuite	 if not Invalid, check Pauline uses this SRTP suite
 */
void mixedEncryption(const string& marieName,
                     const linphone::MediaEncryption marieEncryption,
                     const string& paulineName,
                     const linphone::MediaEncryption paulineEncryption,
                     const bool video,
                     const std::list<linphone::SrtpSuite>& marieSrtpSuiteSetting = {},
                     const linphone::SrtpSuite expectedMarieSuite = linphone::SrtpSuite::Invalid,
                     const linphone::SrtpSuite expectedPaulineSuite = linphone::SrtpSuite::Invalid) {
	// Initialize and start proxy and B2bua servers.
	const auto server = make_shared<B2buaAndProxyServer>("config/flexisip_b2bua.conf");
	ClientBuilder builder{*server->getAgent()};
	builder.setVideoSend(static_cast<OnOff>(video)).setVideoReceive(static_cast<OnOff>(video));
	// Create and register clients.
	auto marie = builder.build(marieName);
	auto pauline = builder.build(paulineName);

	// Establish an audio (and video if enabled) call using given encryption.
	{
		// Marie (caller) calls Pauline (callee).
		const auto marieCallParams = marie.getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		marieCallParams->enableVideo(video);
		if (!marieSrtpSuiteSetting.empty()) {
			marieCallParams->setSrtpSuites(marieSrtpSuiteSetting);
		}
		const auto marieCall = marie.call(pauline, marieCallParams);
		BC_HARD_ASSERT(marieCall != nullptr);

		const auto marieStats = marie.getCurrentCall()->getStats(linphone::StreamType::Audio);
		const auto paulineStats = pauline.getCurrentCall()->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_ENUM_EQUAL(marieStats->getSrtpSource(), marieEncryption);
		BC_HARD_ASSERT_ENUM_EQUAL(paulineStats->getSrtpSource(), paulineEncryption);
		if (expectedMarieSuite != linphone::SrtpSuite::Invalid) {
			BC_HARD_ASSERT_ENUM_EQUAL(marieStats->getSrtpSuite(), expectedMarieSuite);
		}
		if (expectedPaulineSuite != linphone::SrtpSuite::Invalid) {
			BC_HARD_ASSERT_ENUM_EQUAL(paulineStats->getSrtpSuite(), expectedPaulineSuite);
		}

		// We are going through a back-2-back user agent, so the Call-ID headers are not the same.
		const auto paulineCall = ClientCall::getLinphoneCall(pauline.getCurrentCall().value());
		BC_HARD_ASSERT(marieCall->getCallLog()->getCallId() != paulineCall->getCallLog()->getCallId());

		BC_HARD_ASSERT(marie.endCurrentCall(pauline));
	}

	// Establish an audio call using given encryption.
	// Then, update the call to add video.
	// Finally, update the call to remove video.
	if (video) {
		const auto marieCallParams = marie.getCore()->createCallParams(nullptr);
		marieCallParams->setMediaEncryption(marieEncryption);
		marieCallParams->enableVideo(false);
		// Audio call only.
		const auto marieCall = marie.call(pauline, marieCallParams);
		BC_HARD_ASSERT(marieCall != nullptr);

		const auto paulineCall = ClientCall::getLinphoneCall(pauline.getCurrentCall().value());
		auto marieStats = marieCall->getStats(linphone::StreamType::Audio);
		auto paulineStats = paulineCall->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_ENUM_EQUAL(marieStats->getSrtpSource(), marieEncryption);
		BC_HARD_ASSERT_ENUM_EQUAL(paulineStats->getSrtpSource(), paulineEncryption);
		BC_HARD_ASSERT(!marieCall->getCurrentParams()->videoEnabled());
		BC_HARD_ASSERT(!paulineCall->getCurrentParams()->videoEnabled());

		// Update call to add video.
		// The callUpdate checks that video is enabled.
		marieCallParams->enableVideo(true);
		BC_HARD_ASSERT(marie.callUpdate(pauline, marieCallParams));

		marieStats = marieCall->getStats(linphone::StreamType::Audio);
		paulineStats = paulineCall->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_ENUM_EQUAL(marieStats->getSrtpSource(), marieEncryption);
		BC_HARD_ASSERT_ENUM_EQUAL(paulineStats->getSrtpSource(), paulineEncryption);

		// Update call to remove video.
		// The callUpdate checks that video is disabled.
		marieCallParams->enableVideo(false);
		BC_HARD_ASSERT(marie.callUpdate(pauline, marieCallParams));

		marieStats = marieCall->getStats(linphone::StreamType::Audio);
		paulineStats = paulineCall->getStats(linphone::StreamType::Audio);
		BC_HARD_ASSERT_ENUM_EQUAL(marieStats->getSrtpSource(), marieEncryption);
		BC_HARD_ASSERT_ENUM_EQUAL(paulineStats->getSrtpSource(), paulineEncryption);

		BC_HARD_ASSERT(marie.endCurrentCall(pauline));
	}
}

void sdesToZrtpCall() {
	// sdes to zrtp
	mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP, false, {},
	                defaultClientSdesSrtpSuite, defaultZrtpSrtpSuite);
	mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, zrtpUri, linphone::MediaEncryption::ZRTP, true, {},
	                defaultClientSdesSrtpSuite, defaultZrtpSrtpSuite);
	// zrtp to sdes
	mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP, false, {},
	                defaultZrtpSrtpSuite, defaultServerSdesSrtpSuite);
	mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, srtpUri, linphone::MediaEncryption::SRTP, true, {},
	                defaultZrtpSrtpSuite, defaultServerSdesSrtpSuite);
}

void sdesToDtlsCall() {
	// sdes to dtls
	mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, false, {},
	                defaultClientSdesSrtpSuite, defaultDtlsSrtpSuite);
	mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true, {},
	                defaultClientSdesSrtpSuite, defaultDtlsSrtpSuite);
	// dtls to sdes
	mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP, false, {},
	                defaultDtlsSrtpSuite, defaultServerSdesSrtpSuite);
	mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, srtpUri, linphone::MediaEncryption::SRTP, true, {},
	                defaultDtlsSrtpSuite, defaultServerSdesSrtpSuite);
}

template <const bool enableVideo>
void sdesToSdes256Call() {
	// Call from SDES to SDES256
	mixedEncryption(srtpUri, linphone::MediaEncryption::SRTP, srtp256Uri, linphone::MediaEncryption::SRTP, enableVideo,
	                {linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA132},
	                linphone::SrtpSuite::AESCM128HMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA180);
	// Call from SDES256 to SDES
	mixedEncryption(srtp256Uri, linphone::MediaEncryption::SRTP, srtpUri, linphone::MediaEncryption::SRTP, enableVideo,
	                {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132},
	                linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AESCM128HMACSHA180);
	// Call from SDES256 to SDES256gcm
	mixedEncryption(srtp256Uri, linphone::MediaEncryption::SRTP, "sip:b2bua_srtpgcm@sip.example.org",
	                linphone::MediaEncryption::SRTP, enableVideo,
	                {linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AES256CMHMACSHA132},
	                linphone::SrtpSuite::AES256CMHMACSHA180, linphone::SrtpSuite::AEADAES256GCM);
}

void zrtpToDtlsCall() {
	// zrtp to dtls
	mixedEncryption(zrtpUri, linphone::MediaEncryption::ZRTP, dtlsUri, linphone::MediaEncryption::DTLS, false);
	mixedEncryption(zrtpUri, linphone::MediaEncryption::SRTP, dtlsUri, linphone::MediaEncryption::DTLS, true);

	// dtls to zrtp
	mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, false);
	mixedEncryption(dtlsUri, linphone::MediaEncryption::DTLS, zrtpUri, linphone::MediaEncryption::ZRTP, true);
}

template <const linphone::MediaEncryption mediaEncryption, const bool enableVideo>
void forwardMediaEncryption() {
	// Use URI not matching anything in the b2bua server config, so outgoing media encryption shall match incoming one.
	const auto marieName = "sip:marie@sip.example.org"s;
	const auto paulineName = "sip:pauline@sip.example.org"s;
	mixedEncryption(marieName, mediaEncryption, paulineName, mediaEncryption, enableVideo);
}

template <const string& codec>
void videoCallWithForcedCodec() {
	// Initialize and start the proxy and B2bua server.
	B2buaAndProxyServer server{"config/flexisip_b2bua.conf"};
	// Create and register clients.
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

	const auto disableAllVideoCodecs = [](const std::shared_ptr<linphone::Core>& core) {
		auto payloadTypes = core->getVideoPayloadTypes();
		for (const auto& pt : payloadTypes) {
			pt->enable(false);
		}
	};

	// Force usage of the requested codec.
	disableAllVideoCodecs(marie.getCore());
	disableAllVideoCodecs(pauline.getCore());
	payloadTypeMarie->enable(true);
	payloadTypePauline->enable(true);

	// Place a video call.
	BC_HARD_ASSERT(marie.callVideo(pauline) != nullptr);
	BC_HARD_ASSERT(pauline.endCurrentCall(marie));
}

const string VP8 = "vp8"s;
// const char H264[] = "h264";

TestSuite _{
    "B2bua::trenscrypter",
    {
        CLASSY_TEST(sdesToZrtpCall),
        CLASSY_TEST(sdesToDtlsCall),
        CLASSY_TEST(sdesToSdes256Call<false>),
        CLASSY_TEST(sdesToSdes256Call<true>),
        CLASSY_TEST(zrtpToDtlsCall),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::None, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::None, true>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::DTLS, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::DTLS, true>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::SRTP, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::SRTP, true>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::ZRTP, false>)),
        CLASSY_TEST((forwardMediaEncryption<linphone::MediaEncryption::ZRTP, true>)),
        // H264 is not supported in flexisip sdk's build, so even if the b2bua core is able to
        // relay H264 video without decoding, the test client cannot support it.
        // Uncomment when H264 support can be built.
        // CLASSY_TEST(trenscrypter__video_call_with_forced_codec<H264>),
        CLASSY_TEST(videoCallWithForcedCodec<VP8>),
    },
};

} // namespace
} // namespace flexisip::tester::b2buatester