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

#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "linphone++/linphone.hh"

#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"
#include "utils/observable.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip::voicemail {

class CallHandler;
/**
 * @brief Be notified when a call handler has finished to handle a call.
 */
class CallHandlerObserver {
public:
	virtual ~CallHandlerObserver() = default;

	virtual void onCallHandled(const std::shared_ptr<linphone::Call>&) noexcept = 0;
};

/**
 * Handle all logic behind the voicemail recording for an incoming call
 */
class CallHandler : public std::enable_shared_from_this<CallHandler>,
                    public Observable<CallHandlerObserver>,
                    public linphone::PlayerListener,
                    public linphone::CallListener {
public:
	struct RecordingParameters {
		std::chrono::seconds callMaxDuration{};
		std::filesystem::path voicemailStoragePath{};
		sofiasip::Url slotUrl{};
	};
	struct AnnouncementPaths {
		std::filesystem::path defaultAnnounce;
		std::filesystem::path voicemailAnnounce;
	};

	CallHandler(const std::shared_ptr<linphone::Call>& call,
	            const std::shared_ptr<linphone::Core>& core,
	            const std::shared_ptr<sofiasip::SuRoot>& root,
	            RestClient& restClient,
	            const AnnouncementPaths& announcementsPaths,
	            const RecordingParameters& params)
	    : mLogPrefix(LogManager::makeLogPrefixForInstance(this, "CallHandler")), mCore(core), mCall(call),
	      mFlexiApiClient(restClient), mTimer(root), mAnnouncementsPaths(announcementsPaths),
	      mRecordingParameters(params),
	      mMaxRecordSize(mRecordingParameters.callMaxDuration.count() * kBytesPerSecondOfRecord) {}
	~CallHandler() override = default;

	void playAnnounce(const std::filesystem::path& announcePath);
	void terminateCall();

	// Player listener
	void onEofReached(const std::shared_ptr<linphone::Player>& player) override;

	// Call listener
	void onAckProcessing(const std::shared_ptr<linphone::Call>& call,
	                     const std::shared_ptr<linphone::Headers>& ack,
	                     bool isReceived) override;
	void onStateChanged(const std::shared_ptr<linphone::Call>& call,
	                    linphone::Call::State state,
	                    const std::string& message) override;

	void start();

private:
	enum class CallState {
		pending,
		establishing,
		mediaReady,
	};
	enum class HandlerMode {
		unknown,
		simpleAnnounce,
		voicemailRecording,
	};

	// Bytes per second of recording (approximately 0.1MB/s with uncompressed WAV)
	static constexpr int kBytesPerSecondOfRecord = 1024 * 1024 / 10;

	void onCallStateStreamsRunning();
	void onCallStateEnd();

	void reserveSlot();
	void sendSlotRequest(int accountId);
	void onSlotReserved(const std::shared_ptr<HttpResponse>& rep);
	void uploadVoicemail(const sofiasip::Url& url);

	void handleCallWithoutRecording();

	void notifyCallHandled() {
		notify([this](auto& aObserver) { aObserver.onCallHandled(mCall); });
	}

	const std::string mLogPrefix;
	std::shared_ptr<linphone::Core> mCore;
	const std::shared_ptr<linphone::Call> mCall;
	RestClient& mFlexiApiClient;
	sofiasip::Timer mTimer;

	const AnnouncementPaths& mAnnouncementsPaths;
	RecordingParameters mRecordingParameters;
	std::filesystem::path mRecordPath{};
	const int mMaxRecordSize;

	HandlerMode mHandlerMode{};
	CallState mCallState{};
};

} // namespace flexisip::voicemail