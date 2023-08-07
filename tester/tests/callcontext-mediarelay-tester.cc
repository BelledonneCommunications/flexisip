/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "callcontext-mediarelay.hh"

#include <cstddef>
#include <memory>

#include "sdp-modifier.hh"
#include "sofia-sip/sdp.h"
#include "sofia-sip/sip.h"
#include "sofia-wrapper/sip-header-private.hh"

#include "flexisip/configmanager.hh"
#include "flexisip/logmanager.hh"

#include "mediarelay.hh"

#include "utils/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {

/**
 * 1. Setup a RelayedCall with a first channel
 * 2. Add a second channel
 * 3. Verify that the second channel is the only one in SendRecv mode
 */
void setChannelDestinationsTakesOverPreviousSendRecvBranch() {
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	}};
	proxy.start(); // Load modules
	const auto& agent = proxy.getAgent();
	auto* mediaRelay = dynamic_cast<MediaRelay*>(agent->findModule("MediaRelay").get());
	BC_HARD_ASSERT_TRUE(mediaRelay != nullptr);
	const auto mediaRelayServer = std::make_shared<MediaRelayServer>(mediaRelay);
	MsgSip msg{};
	msg.makeAndInsert<sofiasip::SipHeaderCallID>("test-mediarelay-sendrecv");
	msg.makeAndInsert<sofiasip::SipHeaderCSeq>(0xfeu, ::sip_method_invite);
	msg.makeAndInsert<sofiasip::SipHeaderFrom>("sip:test-mediarelay-sendrecv-from@sip.example.org",
	                                           "test-mediarelay-sendrecv-from-tag");
	RelayedCall relayedCall{mediaRelayServer, msg.getSip()};
	sdp_media_t line{};
	line.m_attributes = nullptr;
	line.m_connections = nullptr;
	line.m_port = 0xdead;
	sdp_session_t session{};
	session.sdp_connection = nullptr;
	session.sdp_media = &line;
	const auto sdpModifier = std::make_shared<SdpModifier>(msg.getHome(), "");
	BC_HARD_ASSERT_TRUE(sdpModifier != nullptr);
	sdpModifier->mSession = &session;
	sdpModifier->mSip = msg.getSip();
	const std::string firstTrid = "first-trid";
	// Setup line 0 & first channel
	relayedCall.initChannels(sdpModifier, "stub-tag", firstTrid, "stub-from_host", "stub-destHost");
	const auto lineIndex = 0;
	const auto isEarlyMedia = true;
	relayedCall.setChannelDestinations(sdpModifier, lineIndex, "stub-ip", 0xdead, 0xdead, "stub-partytag", firstTrid,
	                                   isEarlyMedia);
	const auto& relaySession = relayedCall.getSessions()[lineIndex];
	const auto firstChannel = relaySession->getChannel("stub-partyid", firstTrid);
	BC_HARD_ASSERT_TRUE(firstChannel != nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(firstChannel->getDirection(), RelayChannel::Dir::SendRecv);
	const std::string secondTrid = "second-trid";
	relayedCall.initChannels(sdpModifier, "stub-tag", secondTrid, "stub-from_host", "stub-destHost");

	relayedCall.setChannelDestinations(sdpModifier, lineIndex, "stub-ip", 0xdead, 0xdead, "stub-partytag", secondTrid,
	                                   isEarlyMedia);

	const auto secondChannel = relaySession->getChannel("stub-partyid", secondTrid);
	BC_HARD_ASSERT_TRUE(secondChannel != nullptr);
	BC_ASSERT_CPP_EQUAL(secondChannel->getDirection(), RelayChannel::Dir::SendRecv);
	BC_ASSERT_CPP_EQUAL(firstChannel->getDirection(), RelayChannel::Dir::SendOnly);

	// Smoke test
	relayedCall.removeBranch(secondTrid);
	// Passed if this doesn't crash
	relayedCall.setChannelDestinations(sdpModifier, lineIndex, "stub-ip", 0xdead, 0xdead, "stub-partytag", "third-trid",
	                                   isEarlyMedia);
}

namespace {
TestSuite _("callcontext-mediarelay",
            {
                CLASSY_TEST(setChannelDestinationsTakesOverPreviousSendRecvBranch),
            });
}
} // namespace flexisip::tester
