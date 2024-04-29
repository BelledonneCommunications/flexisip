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

#include "callcontext-mediarelay.hh"

#include <memory>

#include "sdp-modifier.hh"
#include "sofia-sip/sdp.h"
#include "sofia-sip/sip.h"
#include "sofia-wrapper/sip-header-private.hh"

#include "mediarelay.hh"

#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

namespace {

namespace helper {

/*
 * Set up proxy and media-relay servers.
 */
static pair<Server, shared_ptr<MediaRelayServer>> createProxyAndMediaRelayServers() {
	Server proxy{};
	proxy.start();
	auto* mediaRelayModule = dynamic_cast<MediaRelay*>(proxy.getAgent()->findModule("MediaRelay").get());
	const auto mediaRelayServer = make_shared<MediaRelayServer>(mediaRelayModule);
	BC_HARD_ASSERT(mediaRelayServer != nullptr);

	return {std::move(proxy), mediaRelayServer};
}

/*
 * Create a RelayedCall from a stub INVITE request.
 * Also provides SdpModifier objects for describing media sessions of both devices.
 */
static pair<shared_ptr<RelayedCall>, pair<shared_ptr<SdpModifier>, shared_ptr<SdpModifier>>>
createRelayedCallAndSdp(const shared_ptr<MediaRelayServer>& srv) {
	MsgSip msg{};
	msg.makeAndInsert<sofiasip::SipHeaderCallID>("stub-call-id");
	msg.makeAndInsert<sofiasip::SipHeaderCSeq>(0xfeu, ::sip_method_invite);
	msg.makeAndInsert<sofiasip::SipHeaderFrom>("sip:stub-user@sip.example.org", "stub-from-tag");

	auto relayedCall = make_shared<RelayedCall>(srv, msg.getSip());
	return {
	    relayedCall,
	    {
	        make_shared<SdpModifier>(msg.getHome(), ""),
	        make_shared<SdpModifier>(msg.getHome(), ""),
	    },
	};
}

template <int nbMediaSessions>
static void makeDeviceTakeOverSendRecvCapabilities(const shared_ptr<RelayedCall>& call,
                                                   const shared_ptr<SdpModifier>& sdp,
                                                   const string& trId) {
	// Set up media sessions for current device.
	array<sdp_media_t, nbMediaSessions> mediaSessions{};
	sdp_session_t sdpSession{.sdp_connection = nullptr, .sdp_media = &mediaSessions.front()};
	for (int sessionId = 0; sessionId < nbMediaSessions; sessionId++) {
		mediaSessions[sessionId] = {.m_port = 0xdead, .m_connections = nullptr, .m_attributes = nullptr};
		if (sessionId > 0) mediaSessions[sessionId - 1].m_next = &mediaSessions[sessionId];
	}
	sdp->mSession = &sdpSession;

	call->initChannels(sdp, "stub-tag", trId, "stub-from-host", "stub-dest-host");

	// Make device take over SendRecv capabilities for all its media sessions.
	for (int sessionId = 0; sessionId < nbMediaSessions; sessionId++) {
		call->setChannelDestinations(sdp, sessionId, "stub-ip", 0xdead, 0xdead, "stub-party-tag", trId, true);

		const auto channel = call->getSessions()[sessionId]->getChannel("stub-party-id", trId);
		BC_HARD_ASSERT(channel != nullptr);
		BC_HARD_ASSERT_CPP_EQUAL(channel->getDirection(), RelayChannel::Dir::SendRecv);
	}
}
}; // namespace helper

/**
 * 1. Set up a RelayedCall.
 * 2. Make first device take over SendRecv capabilities.
 * 3. Make second device take over SendRecv capabilities.
 * 3. Verify that all corresponding media sessions now have SendRecv capabilities for the second device and SendOnly
 * capabilities for the first device.
 */
template <int nbMediaSessionsFirstDevice, int nbMediaSessionsSecondDevice>
void setChannelDestinationsTakesOverPreviousSendRecvTrId() {
	auto [proxy, mediaRelayServer] = helper::createProxyAndMediaRelayServers();
	auto [call, sdp] = helper::createRelayedCallAndSdp(mediaRelayServer);

	const string fTrId = "first-transaction-id";
	helper::makeDeviceTakeOverSendRecvCapabilities<nbMediaSessionsFirstDevice>(call, sdp.first, fTrId);

	const string sTrId = "second-transaction-id";
	helper::makeDeviceTakeOverSendRecvCapabilities<nbMediaSessionsSecondDevice>(call, sdp.second, sTrId);

	// Verify that all media sessions of the first device now only have SendOnly capabilities.
	for (int session = 0; session < nbMediaSessionsFirstDevice; session++) {
		const auto& previousChannel = call->getSessions()[session]->getChannel("stub-party-id", fTrId);
		BC_ASSERT_CPP_EQUAL(previousChannel->getDirection(), RelayChannel::Dir::SendOnly);
	}

	// Smoke test: passed if this doesn't crash
	call->removeBranch(sTrId);
	for (int sessionId = 0; sessionId < nbMediaSessionsSecondDevice; sessionId++) {
		call->setChannelDestinations(sdp.second, sessionId, "stub-ip", 0xdead, 0xdead, "stub-party-tag", "", true);
	}
}

TestSuite _("CallContextMediaRelay",
            {
                CLASSY_TEST((setChannelDestinationsTakesOverPreviousSendRecvTrId<1, 1>)),
                CLASSY_TEST((setChannelDestinationsTakesOverPreviousSendRecvTrId<1, 2>)),
                CLASSY_TEST((setChannelDestinationsTakesOverPreviousSendRecvTrId<2, 1>)),
                CLASSY_TEST((setChannelDestinationsTakesOverPreviousSendRecvTrId<2, 2>)),
            });

} // namespace
} // namespace flexisip::tester