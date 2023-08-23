/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <map>
#include <memory>
#include <string>
#include <unordered_map>

#include "sdp-modifier.hh"
#include "sofia-sip/sdp.h"
#include "sofia-sip/sip.h"

#include "bctoolbox/tester.h"
#include "linphone++/call.hh"
#include "linphone/api/c-call-stats.h"
#include "linphone/api/c-call.h"
#include "ortp/rtp.h"

#include "flexisip/module.hh"

#include "utils/asserts.hh"
#include "utils/call-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/injected-module.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {

namespace {
const std::map<std::string, std::string> CONFIG{
    {"module::MediaRelay/enabled", "true"},
    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
    // Requesting bind on port 0 to let the kernel find any available port
    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
    {"module::Registrar/enabled", "true"},
    {"module::Registrar/reg-domains", "sip.example.org"},
};
}

/**
 * Freeswitch has been witnessed to provide ICE candidates in its responses (183 & 200) even when the INVITE did *not*
 * contain any ICE candidate. The media relay was thrown off by this and assumed the call was using ICE, so it did not
 * properly masquerade the SDP, resulting in one side not getting audio.
 */
void ice_candidates_in_response_only() {
	InjectedHooks hooks{{
	    .onResponse =
	        [](const auto& responseEvent) {
		        auto& message = *responseEvent->getMsgSip();
		        const auto sip = message.getSip();
		        if (sip->sip_status->st_status != 200) return;
		        if (sip->sip_cseq->cs_method != sip_method_invite) return;

		        auto msg = message.getMsg();
		        const auto sdpModifier = SdpModifier::createFromSipMsg(message.getHome(), sip);
		        BC_ASSERT_TRUE(sdpModifier != nullptr);
		        const auto mediaLine = sdpModifier->mSession->sdp_media;
		        // Break the media port on purpose.
		        // This media is never going to reach its destination unless the media relay fixes it.
		        constexpr decltype(mediaLine->m_port) NEVER_GOING_TO_ANSWER = 666;
		        mediaLine->m_port = NEVER_GOING_TO_ANSWER;
		        // Inject some fake ICE candidates, as if the UA had answered them in its 200 Ok response.
		        sdpModifier->addMediaAttribute(
		            mediaLine, "candidate",
		            "1859934665 1 udp 2130706431 2604:a880:4:1d0::76b:0 24028 typ host generation 0");
		        sdpModifier->addMediaAttribute(
		            mediaLine, "candidate",
		            "6796095525 2 udp 2130706430 2604:a880:4:1d0::76b:0 27151 typ host generation 0");
		        BC_ASSERT_TRUE(sdpModifier->update(msg, sip) != -1);
	        },
	}};
	Server server(CONFIG, &hooks);
	server.start();
	auto builder = server.clientBuilder();
	auto nelly = builder.build("sip:Nelly@sip.example.org");
	auto lola = builder.build("sip:Lola@sip.example.org");

	nelly.call(lola);
}

void early_media_video_sendrecv_takeover() {
	Server server(CONFIG);
	server.start();
	auto builder = server.clientBuilder();
	const auto doorBell =
	    builder.setVideoReceive(OnOff::Off).setVideoSend(OnOff::On).build("sip:door-bell@sip.example.org");
	const auto appUri = "sip:app@sip.example.org";
	const auto app = builder.setVideoReceive(OnOff::On).setVideoSend(OnOff::Off).build(appUri);
	const auto appExtension = builder
	                              // Make sure all RTCP traffic received by the door bell must come from the app
	                              .setRtcpSend(OnOff::Off)
	                              .build(appUri);
	CoreAssert asserter(doorBell, appExtension, app, server);
	const auto callBuilder = doorBell.callBuilder();
	callBuilder.setVideo(OnOff::On).setEarlyMediaSending(OnOff::On);

	auto doorCall = callBuilder.call(appUri);
	BC_HARD_ASSERT_TRUE(appExtension.hasReceivedCallFrom(doorBell));
	auto appExtCall = appExtension.getCurrentCall().value();
	appExtCall.acceptEarlyMedia();

	// Video is received by the app extension
	asserter
	    .iterateUpTo(0x10,
	                 [&doorCall, &appExtCall, &appExtReceivedVideo = appExtCall.videoFrameDecoded()] {
		                 FAIL_IF(doorCall.getState() != linphone::Call::State::OutgoingEarlyMedia);
		                 FAIL_IF(appExtCall.getState() != linphone::Call::State::IncomingEarlyMedia);
		                 FAIL_IF(!appExtReceivedVideo);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(appExtCall.getVideoRtpStats().sent_rtcp_packets, 0);
	BC_ASSERT_CPP_EQUAL(doorCall.getVideoRtpStats().recv_rtcp_packets, 0);

	/**
	 * Test that a second 183 Session Progress takes the SendRecv stream from the app extension
	 */

	BC_HARD_ASSERT_TRUE(app.hasReceivedCallFrom(doorBell));
	const auto appCall = app.getCurrentCall().value();
	appCall.acceptEarlyMedia();

	// The door bell should receive the RTCP stream from the app
	asserter
	    .iterateUpTo(0x10,
	                 [&appReceivedVideo = appExtCall.videoFrameDecoded(), &appCall, &doorCall] {
		                 FAIL_IF(appCall.getVideoRtpStats().sent_rtcp_packets == 0);
		                 FAIL_IF(!appReceivedVideo);
		                 FAIL_IF(doorCall.getVideoRtpStats().recv_rtcp_packets == 0);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
	BC_ASSERT_CPP_EQUAL(appExtCall.getVideoRtpStats().sent_rtcp_packets, 0);
}

void early_media_bidirectional_video() {
	Server server(CONFIG);
	server.start();
	auto builder = server.clientBuilder();
	builder.setVideoReceive(OnOff::On).setVideoSend(OnOff::On);
	const auto paul = builder.build("sip:paul@sip.example.org");
	const auto clem = "sip:clem@sip.example.org";
	const auto clemPhone = builder.build(clem);
	const auto clemLaptop = builder.build(clem);
	CoreAssert asserter(paul, clemPhone, clemLaptop, server);
	const auto callBuilder = paul.callBuilder();
	callBuilder.setVideo(OnOff::On).setEarlyMediaSending(OnOff::On);

	auto paulCall = callBuilder.call(clem);
	BC_HARD_ASSERT_TRUE(clemLaptop.hasReceivedCallFrom(paul));
	BC_HARD_ASSERT_TRUE(clemPhone.hasReceivedCallFrom(paul));
	auto clemPhoneCall = clemPhone.getCurrentCall().value();
	auto clemLaptopCall = clemLaptop.getCurrentCall().value();
	clemPhoneCall.acceptEarlyMedia();

	// As long as only one device accepted the early media, the caller is able to decode video
	asserter
	    .iterateUpTo(
	        0x20,
	        [&paulReceivedVideo = paulCall.videoFrameDecoded(),
	         &phoneReceivedVideo = clemPhoneCall.videoFrameDecoded()] {
		        FAIL_IF(!phoneReceivedVideo);
		        FAIL_IF(!paulReceivedVideo);
		        return ASSERTION_PASSED();
	        },
	        3s)
	    .assert_passed();

	// But as soon as another device sends a 183, it takes over receive capability from the media relay and starts
	// sending packets with a different SSRC than that of the first device. The caller does not recognize this new SSRC
	// and fails to decode video.
	clemLaptopCall.acceptEarlyMedia();
	// Wait for the laptop to successfully decode video
	asserter
	    .iterateUpTo(
	        0x10,
	        [&laptopReceivedVideo = clemLaptopCall.videoFrameDecoded()] {
		        FAIL_IF(!laptopReceivedVideo);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
	// This should have given enough time for everything to settle, and the caller should only be receiving traffic from
	// the laptop now
	asserter
	    .iterateUpTo(8,
	                 [&phoneReceivedVideo = clemPhoneCall.videoFrameDecoded(),
	                  &paulReceivedVideo = paulCall.videoFrameDecoded()] {
		                 FAIL_IF(!phoneReceivedVideo);
		                 FAIL_IF(paulReceivedVideo);
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();
}

namespace {
TestSuite _("MediaRelay",
            {
                CLASSY_TEST(ice_candidates_in_response_only),
                CLASSY_TEST(early_media_video_sendrecv_takeover),
                CLASSY_TEST(early_media_bidirectional_video),
            });
}
} // namespace tester
} // namespace flexisip
