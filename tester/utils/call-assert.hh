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

	class MediaStateListBuilder {
	public:
		MediaStateListBuilder() = default;
		explicit MediaStateListBuilder(MediaStateList mediaStateList) : mMediaStateList(std::move(mediaStateList)){};

		void add(const MediaStateList& mediaStateList) {
			mMediaStateList.insert(mMediaStateList.end(), mediaStateList.begin(), mediaStateList.end());
		}
		[[nodiscard]] const MediaStateList& get() {
			return mMediaStateList;
		}

	private:
		MediaStateList mMediaStateList;
	};

	const ClientCall& call;
	std::optional<linphone::Call::State> state{std::nullopt};
	std::optional<MediaStateList> mediaState{std::nullopt};
	std::optional<bool> videoEnabled{false};
};

/**
 * Assertion tool designed to assert on call states and transmitted media packets.
 */
template <const std::chrono::nanoseconds& sleepBetweenIterations = kDefaultSleepInterval>
class CallAssert {
public:
	using CallAssertionInfoList = std::list<CallAssertionInfo>;

	static const CallAssertionInfo::MediaStateList kAudioSentReceived;
	static const CallAssertionInfo::MediaStateList kNoAudio;
	static const CallAssertionInfo::MediaStateList kVideoSentReceived;
	static const CallAssertionInfo::MediaStateList kNoVideo;
	static const CallAssertionInfo::MediaStateList kAllMediaSentReceived;
	static const CallAssertionInfo::MediaStateList kNoMedia;

	explicit CallAssert(CoreAssert<sleepBetweenIterations>& asserter) : mAsserter(asserter){};

	[[nodiscard]] AssertionResult waitUntil(const CallAssertionInfoList& info,
	                                        std::chrono::duration<double> timeout = std::chrono::seconds{6}) const {
		// First, make sure all call states are as expected.
		auto start = std::chrono::steady_clock::now();
		mAsserter
		    .waitUntil(timeout,
		               [&info] {
			               for (const auto& [call, state, _mediaState, _videoEnabled] : info) {
				               if (state != std::nullopt) {
					               FAIL_IF(!call.assertOnState(*state));
				               }
			               }
			               return ASSERTION_PASSED();
		               })
		    .hard_assert_passed();

		// Then, check that the video is enabled in the params if it needs to be.
		for (const auto& [call, _state, _mediaState, videoEnabled] : info) {
			if (videoEnabled.has_value()) {
				FAIL_IF(call.getCurrentParams()->videoEnabled() != videoEnabled.value());
			}
		}

		// Then, we MUST take a snapshot of RTP stats for all calls
		// WARNING: make sure this is done after call states are as expected, otherwise the snapshot could be wrong
		// for the next step.
		for (const auto& [call, _state, _mediaState, _videoEnabled] : info) {
			call.takeRtpStatsSnapshot();
		}

		// Assert on all provided media types and statuses.
		auto end = std::chrono::steady_clock::now();
		timeout -= (end - start);
		return mAsserter.waitUntil(timeout, [&info] {
			for (const auto& [call, state, mediaState, _videoEnabled] : info) {
				if (mediaState == std::nullopt) {
					continue;
				}
				for (const auto& [type, status] : *mediaState) {
					FAIL_IF(!assertOnMediaState(call, type, status));
				}
			}
			return ASSERTION_PASSED();
		});
	}

private:
	static AssertionResult
	assertOnMediaState(const ClientCall& call, const linphone::StreamType type, CallAssertionInfo::MediaState status) {
		const auto stats = call.getStats(type);
		const auto oldStats = call.getRtpStatsSnapshot()[type];
		// Check that the stats for this stream type have not been created since the snapshot
		FAIL_IF(!stats && oldStats);
		// Check that the stats for this stream type have not been deleted since the snapshot
		FAIL_IF(stats && !oldStats);

		const uint64_t sent = stats ? stats->getRtpPacketSent() : 0;
		const uint64_t oldSent = oldStats.has_value() ? oldStats->packet_sent : 0;
		const uint64_t received = stats ? stats->getRtpPacketRecv() : 0;
		const uint64_t oldReceived = oldStats.has_value() ? oldStats->packet_recv : 0;

		switch (status) {
			case CallAssertionInfo::MediaState::Sent: {
				FAIL_IF(sent <= oldSent);
			} break;
			case CallAssertionInfo::MediaState::Received: {
				FAIL_IF(received <= oldReceived);
			} break;
			case CallAssertionInfo::MediaState::NotSent: {
				FAIL_IF(sent != oldSent);
			} break;
			case CallAssertionInfo::MediaState::NotReceived: {
				FAIL_IF(received != oldReceived);
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
inline const CallAssertionInfo::MediaStateList CallAssert<>::kNoAudio = {
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::NotSent},
    {linphone::StreamType::Audio, CallAssertionInfo::MediaState::NotReceived},
};

template <>
inline const CallAssertionInfo::MediaStateList CallAssert<>::kVideoSentReceived = {
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::Sent},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::Received},
};

template <>
inline const CallAssertionInfo::MediaStateList CallAssert<>::kNoVideo = {
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::NotSent},
    {linphone::StreamType::Video, CallAssertionInfo::MediaState::NotReceived},
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
