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

#include "client-call.hh"

#include <memory>

#include "linphone++/call_params.hh"
#include "linphone++/core.hh"
#include "linphone++/enums.hh"
#include "linphone/api/c-call-stats.h"
#include "linphone/api/c-call.h"
#include "ortp/rtp.h"

using namespace std;

namespace flexisip::tester {

ClientCall::ClientCall(std::shared_ptr<linphone::Call>&& call) : mCall(std::move(call)) {
}

std::optional<ClientCall> ClientCall::tryFrom(std::shared_ptr<linphone::Call>&& maybeCall) {
	if (!maybeCall) return {};
	return ClientCall(std::move(maybeCall));
}

const std::shared_ptr<linphone::Call>& ClientCall::getLinphoneCall(const ClientCall& wrapper) {
	return wrapper.mCall;
}

AssertionResult ClientCall::assertOnState(linphone::Call::State state) const {
	FAIL_IF(getState() != state);
	return ASSERTION_PASSED();
}

AssertionResult ClientCall::assertOnState(linphone::Call::State state, linphone::MediaDirection audio) const {
	FAIL_IF(!assertOnState(state));
	FAIL_IF(getAudioDirection() != audio);
	return ASSERTION_PASSED();
}

AssertionResult ClientCall::assertOnState(linphone::Call::State state,
                                          linphone::MediaDirection audio,
                                          linphone::MediaDirection video) const {
	FAIL_IF(!assertOnState(state, audio));
	FAIL_IF(getAudioDirection() != video);
	return ASSERTION_PASSED();
}

linphone::Status ClientCall::accept() const {
	return mCall->accept();
}

linphone::Status ClientCall::acceptEarlyMedia() const {
	return mCall->acceptEarlyMedia();
}

linphone::Status ClientCall::update(
    const std::function<std::shared_ptr<linphone::CallParams>(std::shared_ptr<linphone::CallParams>&&)>& tweak) const {
	return mCall->update(tweak(mCall->getCore()->createCallParams(mCall)));
}

linphone::Status ClientCall::pause() const {
	return mCall->pause();
}

linphone::Status ClientCall::resume() const {
	return mCall->resume();
}

linphone::Status ClientCall::transferTo(const std::shared_ptr<linphone::Address>& referToAddress) const {
	return mCall->transferTo(referToAddress);
}

linphone::Status ClientCall::transferToAnother(const ClientCall& otherCall) const {
	return mCall->transferToAnother(otherCall.mCall);
}

linphone::Status ClientCall::decline(linphone::Reason reason) const {
	return mCall->decline(reason);
}

linphone::Status ClientCall::terminate() const {
	return mCall->terminate();
}

linphone::Reason ClientCall::getReason() const {
	return mCall->getReason();
}

linphone::Call::State ClientCall::getState() const {
	return mCall->getState();
}

std::shared_ptr<const linphone::Address> ClientCall::getRemoteAddress() const {
	return mCall->getRemoteAddress();
}

std::shared_ptr<const linphone::Address> ClientCall::getRequestAddress() const {
	return mCall->getRequestAddress();
}

std::shared_ptr<const linphone::Address> ClientCall::getReferredByAddress() const {
	return mCall->getReferredByAddress();
}

const ::RtpSession* ClientCall::getRtpSession() const {
	return getMetaRtpTransport().session;
}

const ::RtpTransport& ClientCall::getMetaRtpTransport() const {
	return *::linphone_call_get_meta_rtp_transport(mCall->cPtr(), 0);
}

std::shared_ptr<linphone::CallStats> ClientCall::getStats(linphone::StreamType type) const {
	return mCall->getStats(type);
}

void ClientCall::takeRtpStatsSnapshot() const {
	mRtpStatsSnapshot = RtpStats{getAudioRtpStats(), getVideoRtpStats()};
}

ClientCall::RtpStats ClientCall::getRtpStatsSnapshot() const {
	return mRtpStatsSnapshot;
}

linphone::MediaDirection ClientCall::getAudioDirection() const {
	return mCall->getCurrentParams()->getAudioDirection();
}

std::shared_ptr<linphone::CallStats> ClientCall::getAudioStats() const {
	return mCall->getAudioStats();
}

std::optional<rtp_stats> ClientCall::getAudioRtpStats() const {
	const auto callStats = linphone_call_get_audio_stats(mCall->cPtr());
	if (!callStats) return std::nullopt;
	const auto rtpStats = linphone_call_stats_get_rtp_stats(callStats);
	if (!rtpStats) return std::nullopt;
	return *rtpStats;
}

std::shared_ptr<const linphone::PayloadType> ClientCall::getAudioPayloadType() const {
	return mCall->getCurrentParams()->getUsedAudioPayloadType();
}

const bool& ClientCall::videoFrameDecoded() {
	if (!mListener) {
		mListener = std::make_shared<VideoDecodedListener>();
		mCall->addListener(mListener);
	}

	mListener->mFrameDecoded = false;
	mCall->requestNotifyNextVideoFrameDecoded();

	return mListener->mFrameDecoded;
}

linphone::MediaDirection ClientCall::getVideoDirection() const {
	return mCall->getCurrentParams()->getVideoDirection();
}

std::shared_ptr<linphone::CallStats> ClientCall::getVideoStats() const {
	return mCall->getVideoStats();
}

std::optional<rtp_stats> ClientCall::getVideoRtpStats() const {
	const auto callStats = linphone_call_get_video_stats(mCall->cPtr());
	if (!callStats) return std::nullopt;
	const auto rtpStats = linphone_call_stats_get_rtp_stats(callStats);
	if (!rtpStats) return std::nullopt;
	return *rtpStats;
}

std::shared_ptr<linphone::Core> ClientCall::getCore() const {
	return mCall->getCore();
}

void ClientCall::setStaticPictureFps(float fps) {
	mCall->getCore()->setStaticPictureFps(fps);
}

void ClientCall::addListener(const std::shared_ptr<linphone::CallListener>& listener) const {
	mCall->addListener(listener);
}

std::shared_ptr<linphone::CallParams> ClientCall::createCallParams(const flexisip::tester::ClientCall& call) const {
	return mCall->getCore()->createCallParams(call.mCall);
}

bool ClientCall::operator==(const ClientCall& other) const {
	return other.mCall == mCall;
}

bool ClientCall::operator!=(const ClientCall& other) const {
	return other.mCall != mCall;
}

} // namespace flexisip::tester