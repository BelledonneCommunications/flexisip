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

#pragma once

#include "client-call.hh"
#include "core-assert.hh"

namespace flexisip::tester {

struct CallAssertionInfo {
	enum class MediaState {
		Sent,
		Received,
		NotSent,
		NotReceived,
	};
	using MediaStateList = std::list<std::pair<linphone::StreamType, MediaState>>;

	const ClientCall& call;
	std::optional<linphone::Call::State> state{std::nullopt};
	std::optional<MediaStateList> mediaState{std::nullopt};
};

/**
 * Assertion tool designed to assert on call states and transmitted media packets.
 */
template <const std::chrono::nanoseconds& sleepBetweenIterations = kDefaultSleepInterval>
class CallAssert {
public:
	using CallAssertionInfoList = std::list<CallAssertionInfo>;

	static const CallAssertionInfo::MediaStateList kAudioSentReceived;
	static const CallAssertionInfo::MediaStateList kVideoSentReceived;
	static const CallAssertionInfo::MediaStateList kAllMediaSentReceived;
	static const CallAssertionInfo::MediaStateList kNoMedia;

	explicit CallAssert(CoreAssert<sleepBetweenIterations>& asserter) : mAsserter(asserter){};

	[[nodiscard]] AssertionResult waitUntil(const CallAssertionInfoList& info,
	                                        const std::chrono::duration<double>& timeout = std::chrono::seconds{
	                                            6}) const {
		// First, make sure all call states are as expected.
		mAsserter
		    .waitUntil(timeout / 2,
		               [&info] {
			               for (const auto& [call, state, mediaState] : info) {
				               if (state != std::nullopt) FAIL_IF(!call.assertOnState(*state));
			               }
			               return ASSERTION_PASSED();
		               })
		    .hard_assert_passed();

		// Then, we MUST take a snapshot of RTP stats for all calls
		// WARNING: make sure this is done after call states are as expected, otherwise the snapshot could be wrong for
		// the next step.
		for (const auto& [call, _, __] : info) {
			call.takeRtpStatsSnapshot();
		}

		// Assert on all provided media types and statuses.
		return mAsserter.waitUntil(timeout / 2, [&info] {
			for (const auto& [call, state, mediaState] : info) {
				if (mediaState == std::nullopt) continue;
				for (const auto& [type, status] : *mediaState) {
					FAIL_IF(!assertOnMediaState(call, type, status));
				}
			}
			return ASSERTION_PASSED();
		});
	}

private:
	static AssertionResult
	assertOnMediaState(const ClientCall& call, linphone::StreamType type, CallAssertionInfo::MediaState status) {
		const auto stats = call.getStats(type);
		FAIL_IF(!stats);
		const auto oldStats = call.getRtpStatsSnapshot()[type];
		FAIL_IF(!oldStats);

		switch (status) {
			case CallAssertionInfo::MediaState::Sent: {
				FAIL_IF(stats->getRtpPacketSent() <= oldStats->packet_sent);
			} break;
			case CallAssertionInfo::MediaState::Received: {
				FAIL_IF(stats->getRtpPacketRecv() <= oldStats->packet_recv);
			} break;
			case CallAssertionInfo::MediaState::NotSent: {
				FAIL_IF(stats->getRtpPacketSent() != oldStats->packet_sent);
			} break;
			case CallAssertionInfo::MediaState::NotReceived: {
				FAIL_IF(stats->getRtpPacketRecv() != oldStats->packet_recv);
			} break;
			default:
				throw std::invalid_argument("invalid status (" + std::to_string(static_cast<int>(status)) + ")");
		}

		return ASSERTION_PASSED();
	}

	CoreAssert<sleepBetweenIterations>& mAsserter;
};

template <>
inline const CallAssertionInfo::MediaStateList CallAssert<>::kAudioSentReceived = {
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::Sent},
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::Received},
};

template <>
inline const CallAssertionInfo::MediaStateList CallAssert<>::kVideoSentReceived = {
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::Sent},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::Received},
};

template <>
inline const CallAssertionInfo::MediaStateList CallAssert<>::kAllMediaSentReceived = {
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::Sent},
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::Received},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::Sent},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::Received},
};

template <>
inline const CallAssertionInfo::MediaStateList CallAssert<>::kNoMedia = {
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::NotSent},
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::NotReceived},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::NotSent},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::NotReceived},
};

} // namespace flexisip::tester