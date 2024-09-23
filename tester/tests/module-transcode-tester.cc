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

#include "module-transcode.hh"

#include <chrono>
#include <string>

#include "bctoolbox/tester.h"

#include "flexisip/sofia-wrapper/sdp-parser.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/assertion-debug-print.hh"
#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

namespace flexisip::tester {
namespace {

using namespace std;
using namespace sofiasip;

void transcoderAddsSupportedCodecsInSdp() {
	auto expectedCodecs = unordered_set<string_view>{};
	auto hooks = InjectedHooks{
	    .injectAfterModule = "Transcoder",
	    .onRequest =
	        [&expectedCodecs](const auto& requestEvent) {
		        auto& message = *requestEvent->getMsgSip();
		        const auto sip = message.getSip();
		        if (sip->sip_cseq->cs_method != sip_method_invite) return;

		        const auto* sipPayload = sip->sip_payload;
		        auto sdpParser = SdpParser::parse({sipPayload->pl_data, sipPayload->pl_len});
		        auto& sdpSession = EXPECT_VARIANT(reference_wrapper<SdpSession>).in(sdpParser->session()).get();
		        auto mediasIter = sdpSession.medias().begin();
		        SdpMedia& audio = *mediasIter;
		        BC_HARD_ASSERT_CPP_EQUAL(audio.typeName(), "audio");
		        BC_ASSERT((++mediasIter) == List<SdpMedia>::end()); // No other media line

		        for (const auto& rtpmap : audio.rtpMaps()) {
			        auto found = expectedCodecs.find(rtpmap.encoding());
			        if (found == expectedCodecs.end()) continue;

			        BC_ASSERT_CPP_EQUAL(rtpmap.rate(), 8000);
			        expectedCodecs.erase(found);
			        if (expectedCodecs.empty()) return;
		        }
	        },
	};
	auto proxy = Server{
	    {
	        {"module::Transcoder/enabled", "true"},
	        {"module::MediaRelay/enabled", "false"},
	    },
	    &hooks,
	};
	proxy.start();
	auto asserter = CoreAssert(proxy);
	for (const auto* codec :
	     dynamic_pointer_cast<const Transcoder>(proxy.getAgent()->findModule("Transcoder"))->getSupportedPayloads()) {

		expectedCodecs.emplace(codec->mime_type);
	}
	BC_HARD_ASSERT(2 < expectedCodecs.size());

	constexpr auto invite = ""
	                        "INVITE sip:stub@127.0.0.1:666 SIP/2.0\n"
	                        "From: <sip:from@localhost>;tag=stub-tag-transcoderAddsSupportedCodecsInSdp\n"
	                        "To: sip:to@localhost\n"
	                        "CSeq: 20 INVITE\n"
	                        "Call-ID: stub-callid-transcoderAddsSupportedCodecsInSdp\n"
	                        "Content-Type: application/sdp\n"
	                        "\n"
	                        "v=0\n"
	                        "o=user 111 222 IN IP4 127.0.0.1\n"
	                        "s=Talk\n"
	                        "c=IN IP4 127.0.0.1\n"
	                        "t=0 0\n"
	                        "a=rtcp-xr:rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics\n"
	                        "m=audio 33333 RTP/AVP 0 101\n"
	                        "a=rtpmap:101 telephone-event/8000\n"
	                        "a=rtcp:44444\n"
	                        "a=rtcp-fb:* trr-int 5000\n"
	                        "a=rtcp-fb:* ccm tmmbr\n"
	                        ""sv;

	// Instantiate the client and send the request through an outgoing transaction
	auto client = NtaAgent(proxy.getRoot(), "sip:127.0.0.1:0");
	auto transaction = client.createOutgoingTransaction(invite, "sip:127.0.0.1:"s + proxy.getFirstPort());

	asserter
	    .iterateUpTo(
	        1, [&transaction]() { return LOOP_ASSERTION(transaction->isCompleted()); }, 300ms)
	    .assert_passed();
	// All expected codecs were found
	BC_ASSERT_CPP_EQUAL(expectedCodecs, decltype(expectedCodecs)());
}

auto _ = TestSuite{
    "TranscoderModule",
    {
        CLASSY_TEST(transcoderAddsSupportedCodecsInSdp),
    },
};
} // namespace
} // namespace flexisip::tester
