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

#include <functional>
#include <memory>
#include <optional>

#include "linphone++/call.hh"
#include "linphone++/call_listener.hh"
#include "linphone++/call_stats.hh"
#include "linphone++/enums.hh"
#include "linphone++/payload_type.hh"
#include "ortp/rtp.h"
#include "ortp/rtpsession.h"

#include "asserts.hh"

/*
 * Assert call state only.
 */
#define ASSERT_CALL_1(call, expectedState)                                                                             \
	FAIL_IF(call == nullopt);                                                                                          \
	FAIL_IF(call->getState() != expectedState)

/*
 * Assert call state along with an audio direction.
 */
#define ASSERT_CALL_2(call, expectedState, expectedAudioDirection)                                                     \
	ASSERT_CALL_1(call, expectedState);                                                                                \
	FAIL_IF(call->getAudioDirection() != expectedAudioDirection)

/*
 * Assert call state along with audio and video directions.
 */
#define ASSERT_CALL_3(call, expectedState, expectedAudioDirection, expectedVideoDirection)                             \
	ASSERT_CALL_2(call, expectedState, expectedAudioDirection);                                                        \
	FAIL_IF(call->getVideoDirection() != expectedVideoDirection)

#define GET_ASSERT_CALL_MACRO(_1, _2, _3, _4, NAME, ...) NAME

/*
 * Assert call state.
 * Optionally, you can assert audio and video directions.
 *
 * Usage:
 * - ASSERT_CALL(call, expectedState)
 * - ASSERT_CALL(call, expectedState, expectedAudioDirection)
 * - ASSERT_CALL(call, expectedState, expectedAudioDirection, expectedVideoDirection)
 *
 * With:
 * - call:                    std::optional<ClientCall>
 * - expectedState:           linphone::Call::State
 * - expectedAudioDirection:  linphone::MediaDirection
 * - expectedVideoDirection:  linphone::MediaDirection
 */
#define ASSERT_CALL(...) GET_ASSERT_CALL_MACRO(__VA_ARGS__, ASSERT_CALL_3, ASSERT_CALL_2, ASSERT_CALL_1)(__VA_ARGS__)

namespace flexisip::tester {

template <const std::chrono::nanoseconds&>
class CallAssert;

/**
 * @brief Extends linphone::Call for testing purposes.
 */
class ClientCall {
public:
	class RtpStats {
	public:
		RtpStats() = default;
		RtpStats(const std::optional<rtp_stats>& audio, const std::optional<rtp_stats>& video)
		    : mAudio(audio), mVideo(video){};

		std::optional<rtp_stats> operator[](linphone::StreamType type) const {
			switch (type) {
				case linphone::StreamType::Audio:
					return mAudio;
				case linphone::StreamType::Video:
					return mVideo;
				default:
					throw std::invalid_argument("invalid stream type (" + std::to_string(static_cast<int>(type)) + ")");
			}
		}

	private:
		std::optional<rtp_stats> mAudio{};
		std::optional<rtp_stats> mVideo{};
	};

	static std::optional<ClientCall> tryFrom(std::shared_ptr<linphone::Call>&&);
	/* CHEATS ~~ Use only for quick prototyping */
	static const std::shared_ptr<linphone::Call>& getLinphoneCall(const ClientCall&);

	AssertionResult assertOnState(linphone::Call::State state) const;
	AssertionResult assertOnState(linphone::Call::State state, linphone::MediaDirection audio) const;
	AssertionResult
	assertOnState(linphone::Call::State state, linphone::MediaDirection audio, linphone::MediaDirection video) const;

	linphone::Status accept() const;
	linphone::Status acceptEarlyMedia() const;
	linphone::Status
	update(const std::function<std::shared_ptr<linphone::CallParams>(std::shared_ptr<linphone::CallParams>&&)>&) const;
	linphone::Status pause() const;
	linphone::Status resume() const;
	linphone::Status transferTo(const std::shared_ptr<linphone::Address>& referToAddress) const;
	linphone::Status transferToAnother(const ClientCall& otherCall) const;
	linphone::Status decline(linphone::Reason) const;
	linphone::Status terminate() const;

	linphone::Reason getReason() const;
	linphone::Call::State getState() const;

	std::shared_ptr<const linphone::Address> getRemoteAddress() const;
	std::shared_ptr<const linphone::Address> getRequestAddress() const;
	std::shared_ptr<const linphone::Address> getReferredByAddress() const;

	const ::RtpSession* getRtpSession() const;
	const ::RtpTransport& getMetaRtpTransport() const;
	std::shared_ptr<linphone::CallStats> getStats(linphone::StreamType type) const;

	/**
	 * @brief Generate an RTP stats snapshot for all enabled media types.
	 */
	void takeRtpStatsSnapshot() const;
	RtpStats getRtpStatsSnapshot() const;

	linphone::MediaDirection getAudioDirection() const;
	std::shared_ptr<linphone::CallStats> getAudioStats() const;
	std::optional<rtp_stats> getAudioRtpStats() const;
	std::shared_ptr<const linphone::PayloadType> getAudioPayloadType() const;

	const bool& videoFrameDecoded();
	linphone::MediaDirection getVideoDirection() const;
	std::shared_ptr<linphone::CallStats> getVideoStats() const;
	std::optional<rtp_stats> getVideoRtpStats() const;

	std::string getCallId() const;

	std::shared_ptr<linphone::Core> getCore() const;

	void setStaticPictureFps(float fps);

	void addListener(const std::shared_ptr<linphone::CallListener>& listener) const;
	std::shared_ptr<linphone::CallParams> createCallParams(const ClientCall& call) const;

	bool operator==(const ClientCall& other) const;
	bool operator!=(const ClientCall& other) const;

private:
	class VideoDecodedListener : public linphone::CallListener {
	public:
		bool mFrameDecoded = false;

	private:
		void onNextVideoFrameDecoded(const std::shared_ptr<linphone::Call>&) override {
			mFrameDecoded = true;
		}
	};

	explicit ClientCall(std::shared_ptr<linphone::Call>&&);

	mutable RtpStats mRtpStatsSnapshot{};
	std::shared_ptr<linphone::Call> mCall{};
	std::shared_ptr<VideoDecodedListener> mListener{};
};

} // namespace flexisip::tester