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

#include <map>
#include <memory>
#include <string>

#include "sofia-sip/sip.h"

#include "bctoolbox/tester.h"
#include "linphone++/call.hh"
#include "ortp/rtp.h"

#include "flexisip/sofia-wrapper/sdp-parser.hh"

#include "sdp-modifier.hh"
#include "utils/asserts.hh"
#include "utils/call-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/core-assert.hh"
#include "utils/injected-module-info.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

using namespace std;

namespace flexisip::tester {

namespace {
const std::map<std::string, std::string> CONFIG{
    {"module::MediaRelay/enabled", "true"},
    {"module::MediaRelay/prevent-loops", "false"}, // Allow loopback to localnetwork
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
	InjectedHooks hooks{
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
	};
	Server server(CONFIG, &hooks);
	server.start();
	ClientBuilder builder{*server.getAgent()};
	auto nelly = builder.build("sip:Nelly@sip.example.org");
	auto lola = builder.build("sip:Lola@sip.example.org");

	nelly.call(lola);
}

class CheckForIceCandidatesInResponse : public linphone::CoreListener {
public:
	void onCallStateChanged(const std::shared_ptr<linphone::Core>&,
	                        const std::shared_ptr<linphone::Call>& call,
	                        linphone::Call::State state,
	                        const std::string&) override {
		switch (state) {
			case linphone::Call::State::Connected:
				BC_ASSERT_TRUE(
				    call->getRemoteParams()->hasCustomSdpMediaAttribute(linphone::StreamType::Audio, "candidate"));
				break;
			default:
				break;
		}
	}
};

// Set up an audio call between two cores with ICE enabled on both.
// Verify that the media relay does not redact the candidates out of the answer
void ice_candidates_are_not_erased_in_a_valid_context() {
	Server server(CONFIG);
	server.start();
	ClientBuilder builder{*server.getAgent()};
	builder.setIce(OnOff::On);
	auto nelly = builder.build("sip:Nelly@sip.example.org");
	auto lola = builder.build("sip:Lola@sip.example.org");
	nelly.addListener(std::make_shared<CheckForIceCandidatesInResponse>());

	nelly.call(lola);
}

void relay_candidates_should_not_be_added_to_ice_reinvites() {
	const auto& noCandidateFound = "<No ICE relay candidate found>"s;
	auto anyRelayCandidate = noCandidateFound;
	auto hooks = InjectedHooks{
	    .injectAfterModule = "MediaRelay",
	    .onRequest =
	        [&](const auto& request) {
		        using namespace sofiasip;

		        const auto* sip = request->getSip();
		        if (sip->sip_request->rq_method != sip_method_invite) return;

		        const auto* sipPayload = sip->sip_payload;
		        auto sdpParser = SdpParser::parse({sipPayload->pl_data, sipPayload->pl_len});
		        auto& sdpSession = EXPECT_VARIANT(reference_wrapper<SdpSession>).in(sdpParser->session()).get();
		        for (auto& media : sdpSession.medias()) {
			        for (const auto& attribute : media.attributes().find("candidate")) {
				        const auto& value = attribute.value();
				        if (value.find("typ relay") == string_view::npos) continue;

				        // Found an ICE candidate added by the media relay. Let's stop here
				        anyRelayCandidate = value;
				        return;
			        }
		        }

		        return;
	        },
	};
	auto server = Server(CONFIG, &hooks);
	server.start();
	auto builder = ClientBuilder(*server.getAgent());
	builder.setIce(OnOff::On).setVideoReceive(OnOff::On).setVideoSend(OnOff::On);
	auto inviter = builder.build("sip:inviter@sip.example.org");
	auto recipient = builder.build("sip:recipient@sip.example.org");
	auto asserter = CoreAssert(inviter, server, recipient);

	const auto& call = inviter.invite(recipient);
	BC_HARD_ASSERT(call != nullptr);
	BC_HARD_ASSERT(recipient.hasReceivedCallFrom(inviter).assert_passed());
	recipient.getCurrentCall()->accept();
	// Initial INVITE contains relay candidates
	BC_ASSERT(!anyRelayCandidate.empty());
	anyRelayCandidate = noCandidateFound;

	asserter
	    .iterateUpTo(
	        120, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::Updating); }, 2700ms)
	    .assert_passed();
	// ICE re-INVITE does not contain relay candidates
	BC_ASSERT_CPP_EQUAL(anyRelayCandidate, noCandidateFound);
	anyRelayCandidate = noCandidateFound;

	// Video re-INVITE
	asserter
	    .iterateUpTo(
	        3,
	        [&] {
		        // Wait for ICE reinvite to complete
		        return LOOP_ASSERTION(call->getState() == linphone::Call::State::StreamsRunning);
	        },
	        750ms)
	    .assert_passed();
	const auto& enableVideo = call->getCore()->createCallParams(call);
	enableVideo->enableVideo(true);
	call->update(enableVideo);
	asserter
	    .iterateUpTo(
	        5, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::StreamsRunning); }, 600ms)
	    .assert_passed();
	// Video re-INVITE contains relay candidates
	BC_ASSERT(!anyRelayCandidate.empty());
	anyRelayCandidate = noCandidateFound;

	asserter
	    .iterateUpTo(
	        120, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::Updating); }, 4s)
	    .assert_passed();
	// Video ICE re-INVITE does not contain relay candidates
	BC_ASSERT_CPP_EQUAL(anyRelayCandidate, noCandidateFound);
}

/*
 * Test address masquerading in SDP.
 *
 * A call (audio-only) is established between an inviter and a recipient.
 * Later on, the call is updated (audio and video).
 * Test that address masquerading is correctly applied to INVITE and re-INVITE requests along with their corresponding
 * responses.
 */
void address_masquerading_in_sdp_with_call_update() {
	using namespace sofiasip;
	string hostAfterRequest = "unexpected"s;
	string hostAfterResponse = "unexpected"s;
	const auto getHostInMediaConnection = [](const sip_t* sip, string& host) {
		// Get SDP session.
		const auto* sipPayload = sip->sip_payload;
		BC_HARD_ASSERT(sipPayload != nullptr);
		const auto sdpParser = SdpParser::parse({sipPayload->pl_data, sipPayload->pl_len});
		auto& session = EXPECT_VARIANT(reference_wrapper<SdpSession>).in(sdpParser->session()).get();

		if (sip->sip_cseq->cs_seq == 20) {
			auto& media = *(session.medias().begin());
			BC_HARD_ASSERT_CPP_EQUAL(media.typeName(), "audio"); // media descriptor for audio is on first line
			host = (*media.connections().begin()).address();
		}
		if (sip->sip_cseq->cs_seq == 22) {
			auto& media = *(++session.medias().begin());
			BC_HARD_ASSERT_CPP_EQUAL(media.typeName(), "video"); // media descriptor for video is on second line
			host = (*media.connections().begin()).address();
		}
	};
	auto hooks = InjectedHooks{
	    .injectAfterModule = "MediaRelay",
	    .onRequest =
	        [&](const auto& request) {
		        const auto* sip = request->getSip();
		        if (!sip or !sip->sip_request or sip->sip_request->rq_method != sip_method_invite or !sip->sip_cseq) {
			        return;
		        }
		        getHostInMediaConnection(sip, hostAfterRequest);
	        },
	    .onResponse =
	        [&](const auto& response) {
		        const auto* sip = response->getSip();
		        if (!sip or !sip->sip_cseq or sip->sip_cseq->cs_method != sip_method_invite or !sip->sip_status or
		            sip->sip_status->st_status != 200) {
			        return;
		        }
		        getHostInMediaConnection(sip, hostAfterResponse);
	        },
	};

	// Server configuration.
	const auto serverIPAddress = "127.0.0.2"s;
	auto config = map<string, string>{{"global/transports", "sip:" + serverIPAddress + ":0"}};
	config.merge(map<string, string>{CONFIG});

	// Instantiate server and clients.
	auto server = Server(config, &hooks);
	server.start();
	auto builder = ClientBuilder(*server.getAgent());
	builder.setIce(OnOff::On).setVideoReceive(OnOff::On).setVideoSend(OnOff::On);
	auto inviter = builder.build("sip:inviter@sip.example.org");
	auto recipient = builder.build("sip:recipient@sip.example.org");
	auto asserter = CoreAssert(inviter, server, recipient);

	// Initiate call.
	const auto& call = inviter.invite(recipient);
	BC_HARD_ASSERT(call != nullptr);
	recipient.hasReceivedCallFrom(inviter).hard_assert_passed();
	recipient.getCurrentCall()->accept();
	asserter
	    .iterateUpTo(
	        0x20, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::Updating); }, 2s)
	    .hard_assert_passed();
	asserter
	    .iterateUpTo(
	        0x20, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::StreamsRunning); }, 2s)
	    .hard_assert_passed();

	// Verify that address masquerading was correctly applied.
	BC_ASSERT_CPP_EQUAL(hostAfterRequest, serverIPAddress);
	BC_ASSERT_CPP_EQUAL(hostAfterResponse, serverIPAddress);
	hostAfterRequest = hostAfterResponse = "unexpected"s; // Reset.

	// Video re-INVITE (wait for ICE re-INVITE to complete).
	const auto& enableVideo = call->getCore()->createCallParams(call);
	enableVideo->enableVideo(true);
	call->update(enableVideo);
	asserter
	    .iterateUpTo(
	        0x20, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::Updating); }, 2s)
	    .hard_assert_passed();
	asserter
	    .iterateUpTo(
	        0x20, [&] { return LOOP_ASSERTION(call->getState() == linphone::Call::State::StreamsRunning); }, 2s)
	    .hard_assert_passed();

	// Verify that address masquerading was correctly applied.
	BC_ASSERT_CPP_EQUAL(hostAfterRequest, serverIPAddress);
	BC_ASSERT_CPP_EQUAL(hostAfterResponse, serverIPAddress);

	BC_ASSERT(recipient.endCurrentCall(inviter));
}

void early_media_video_sendrecv_takeover() {
	Server server(CONFIG);
	server.start();
	ClientBuilder builder{*server.getAgent()};
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

	// The doorbell should receive the RTCP stream from the app
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

/*
 * A call is established between a caller and a callee. The caller has one device, the callee has two devices.
 * Test that when called devices accept the call with early media one after the other, the video received from the
 * caller comes from the last device that accepted the call.
 *
 * This feature is developed for a very specific use case: https://bugs.linphone.org/view.php?id=11339#c53679
 */
void early_media_bidirectional_video() {
	Server server(CONFIG);
	server.start();
	ClientBuilder builder{*server.getAgent()};
	builder.setVideoReceive(OnOff::On).setVideoSend(OnOff::On);
	const auto caller = builder.build("sip:caller@sip.example.org");
	const auto callee = "sip:callee@sip.example.org";
	const auto calleePhone = builder.build(callee + ";device=phone"s);
	const auto calleeLaptop = builder.build(callee + ";device=laptop"s);
	CoreAssert asserter(caller, calleePhone, calleeLaptop, server);
	const auto callBuilder = caller.callBuilder();
	callBuilder.setVideo(OnOff::On).setEarlyMediaSending(OnOff::On);

	auto callerCall = callBuilder.call(callee);
	BC_HARD_ASSERT_TRUE(calleePhone.hasReceivedCallFrom(caller));
	BC_HARD_ASSERT_TRUE(calleeLaptop.hasReceivedCallFrom(caller));
	auto calleePhoneCall = calleePhone.getCurrentCall().value();
	auto calleeLaptopCall = calleeLaptop.getCurrentCall().value();
	calleePhoneCall.acceptEarlyMedia();
	calleePhoneCall.setStaticPictureFps(15.0f);

	// Check that only the laptop is unable to decode the video, as it has not yet accepted the call with early media.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&callerReceivedVideo = callerCall.videoFrameDecoded(),
	         &calleePhoneReceivedVideo = calleePhoneCall.videoFrameDecoded(),
	         &calleeLaptopReceivedVideo = calleeLaptopCall.videoFrameDecoded(), &callerCall, &calleePhoneCall,
	         &calleeLaptopCall] {
		        FAIL_IF(!callerReceivedVideo);
		        FAIL_IF(!calleePhoneReceivedVideo);
		        FAIL_IF(calleeLaptopReceivedVideo);
		        FAIL_IF(callerCall.getRtpSession()->rcv.ssrc != calleePhoneCall.getRtpSession()->snd.ssrc);
		        FAIL_IF(callerCall.getRtpSession()->rcv.ssrc == calleeLaptopCall.getRtpSession()->snd.ssrc);
		        return ASSERTION_PASSED();
	        },
	        3s)
	    .assert_passed();

	// But as soon as another device sends a 183 (here: the laptop), it takes over receive capability from the media
	// relay and starts sending packets with a different SSRC than that of the first device.
	calleeLaptopCall.acceptEarlyMedia();
	calleeLaptopCall.setStaticPictureFps(15.0f);

	// Check the source of the traffic received by the caller now comes from the second device (laptop). This is done by
	// verifying that the SSRC received by the caller now matches the SSRC from the laptop.
	asserter
	    .iterateUpTo(
	        0x20,
	        [&callerCall, &calleePhoneCall, &calleeLaptopCall] {
		        FAIL_IF(callerCall.getRtpSession()->rcv.ssrc == calleePhoneCall.getRtpSession()->snd.ssrc);
		        FAIL_IF(callerCall.getRtpSession()->rcv.ssrc != calleeLaptopCall.getRtpSession()->snd.ssrc);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();

	// Make sure all participants are now receiving video (need to wait a few seconds).
	asserter
	    .iterateUpTo(
	        0x20,
	        [&callerReceivedVideo = callerCall.videoFrameDecoded(),
	         &calleePhoneReceivedVideo = calleePhoneCall.videoFrameDecoded(),
	         &calleeLaptopReceivedVideo = calleeLaptopCall.videoFrameDecoded()] {
		        FAIL_IF(!callerReceivedVideo);
		        FAIL_IF(!calleePhoneReceivedVideo);
		        FAIL_IF(!calleeLaptopReceivedVideo);
		        return ASSERTION_PASSED();
	        },
	        3s)
	    .assert_passed();
}

namespace {
TestSuite _("MediaRelay",
            {
                CLASSY_TEST(ice_candidates_in_response_only),
                CLASSY_TEST(ice_candidates_are_not_erased_in_a_valid_context),
                CLASSY_TEST(relay_candidates_should_not_be_added_to_ice_reinvites),
                CLASSY_TEST(address_masquerading_in_sdp_with_call_update),
                CLASSY_TEST(early_media_video_sendrecv_takeover),
                CLASSY_TEST(early_media_bidirectional_video),
            });
}

} // namespace flexisip::tester