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

#include <filesystem>

#include "flexi-stats.hh"

using namespace std;
using namespace flexisip;
using namespace flexiapi;
using namespace nlohmann;

FlexiStats::FlexiStats(sofiasip::SuRoot& root,
                       const std::string& host,
                       const std::string& port,
                       const std::string& apiPrefix,
                       const std::string& token)
    : mRestClient(Http2Client::make(root, host, port),
                  HttpHeaders{
                      {"accept", "application/json"},
                      {"content-type", "application/json"},
                      {"x-api-key"s, token},
                  }),
      mApiPrefix{filesystem::path{"/" + apiPrefix + "/."}.lexically_normal().string()} {
}

void FlexiStats::successCallback(const std::string& id) {
	mOngoingIds.erase(id);

	if (const auto& waitingPatchesForId = mWaitingPatches.find(id); waitingPatchesForId != mWaitingPatches.end()) {
		auto& waitingPatches = waitingPatchesForId->second;
		waitingPatches.front()();
		waitingPatches.pop();
		if (waitingPatches.empty()) mWaitingPatches.erase(id);
	}
}
void FlexiStats::errorCallback(const std::string& id) {
	mOngoingIds.erase(id);
	if (const auto& waitingPatchesForId = mWaitingPatches.find(id); waitingPatchesForId != mWaitingPatches.end()) {
		LOGE << "Error while posting stats to FlexiStats API, [" << waitingPatchesForId->second.size()
		     << "] updates are dropped";
		mWaitingPatches.erase(id);
	}
}
void FlexiStats::addPatchToWaitingQueue(const std::string& id, std::function<void()>&& patch) {
	if (const auto& waitingPatches = mWaitingPatches.find(id); waitingPatches == mWaitingPatches.end()) {
		mWaitingPatches[id] = queue<std::function<void()>>{};
		mWaitingPatches[id].emplace(std::move(patch));
	} else {
		waitingPatches->second.emplace(std::move(patch));
	}
}

void FlexiStats::postMessage(const Message& message) {
	mOngoingIds.emplace(message.id);

	mRestClient.post(
	    toApiPath("messages"), message, [this, id = message.id](const auto&, const auto&) { successCallback(id); },
	    [this, id = message.id](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + message.id + "]",
	    getLogPrefix(__func__) + " request error for id["s + message.id + "]");
}

void FlexiStats::notifyMessageDeviceResponse(const string& messageId,
                                             const ApiFormattedUri& sipUri,
                                             const std::string& deviceId,
                                             const MessageDeviceResponse& messageDeviceResponse) {
	if (mOngoingIds.count(messageId) != 0) {
		auto patch = [this, messageId, sipUri, deviceId, messageDeviceResponse] {
			notifyMessageDeviceResponsePatch(messageId, sipUri, deviceId, messageDeviceResponse);
		};
		addPatchToWaitingQueue(messageId, std::move(patch));
		return;
	}

	notifyMessageDeviceResponsePatch(messageId, sipUri, deviceId, messageDeviceResponse);
}
void FlexiStats::notifyMessageDeviceResponsePatch(const string& messageId,
                                                  const ApiFormattedUri& sipUri,
                                                  const std::string& deviceId,
                                                  const MessageDeviceResponse& messageDeviceResponse) {
	mOngoingIds.emplace(messageId);
	mRestClient.patch(
	    toApiPath("messages/" + messageId + "/to/" + string(sipUri) + "/devices/" + deviceId), messageDeviceResponse,
	    [this, id = messageId](const auto&, const auto&) { successCallback(id); },
	    [this, id = messageId](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + messageId + "]",
	    getLogPrefix(__func__) + " request error for id["s + messageId + "]");
}

void FlexiStats::postCall(const Call& call) {
	mOngoingIds.emplace(call.id);

	mRestClient.post(
	    toApiPath("calls"), call, [this, id = call.id](const auto&, const auto&) { successCallback(id); },
	    [this, id = call.id](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + call.id + "]",
	    getLogPrefix(__func__) + " request error for id["s + call.id + "]");
}

void FlexiStats::updateCallDeviceState(const string& callId,
                                       const string& deviceId,
                                       const CallDeviceState& callDeviceState) {
	if (mOngoingIds.count(callId) != 0) {
		auto patch = [this, callId, deviceId, callDeviceState] {
			updateCallDeviceStatePatch(callId, deviceId, callDeviceState);
		};
		addPatchToWaitingQueue(callId, std::move(patch));
		return;
	}

	updateCallDeviceStatePatch(callId, deviceId, callDeviceState);
}
void FlexiStats::updateCallDeviceStatePatch(const std::string& callId,
                                            const std::string& deviceId,
                                            const CallDeviceState& callDeviceState) {
	mOngoingIds.emplace(callId);
	mRestClient.patch(
	    toApiPath("calls/" + callId + "/devices/" + deviceId), callDeviceState,
	    [this, id = callId](const auto&, const auto&) { successCallback(id); },
	    [this, id = callId](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + callId + "]",
	    getLogPrefix(__func__) + " request error for id["s + callId + "]");
}

void FlexiStats::updateCallState(const string& callId, const ISO8601Date& endedAt) {
	if (mOngoingIds.count(callId) != 0) {
		auto patch = [this, callId, endedAt] { updateCallStatePatch(callId, endedAt); };
		addPatchToWaitingQueue(callId, std::move(patch));
		return;
	}

	updateCallStatePatch(callId, endedAt);
}
void FlexiStats::updateCallStatePatch(const string& callId, const ISO8601Date& endedAt) {
	mOngoingIds.emplace(callId);
	mRestClient.patch(
	    toApiPath("calls/" + callId), optional{json{{"ended_at", endedAt}}},
	    [this, id = callId](const auto&, const auto&) { successCallback(id); },
	    [this, id = callId](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + callId + "]",
	    getLogPrefix(__func__) + " request error for id["s + callId + "]");
}

void FlexiStats::postConference(const Conference& conference) {
	mOngoingIds.emplace(conference.id);

	mRestClient.post(
	    toApiPath("conferences"), conference,
	    [this, id = conference.id](const auto&, const auto&) { successCallback(id); },
	    [this, id = conference.id](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + conference.id + "]",
	    getLogPrefix(__func__) + " request error for id["s + conference.id + "]");
}

void FlexiStats::notifyConferenceEnded(const string& conferenceId, const ISO8601Date& endedAt) {
	if (mOngoingIds.count(conferenceId) != 0) {
		auto patch = [this, conferenceId, endedAt] { notifyConferenceEndedPatch(conferenceId, endedAt); };
		addPatchToWaitingQueue(conferenceId, std::move(patch));
		return;
	}

	notifyConferenceEndedPatch(conferenceId, endedAt);
}
void FlexiStats::notifyConferenceEndedPatch(const string& conferenceId, const ISO8601Date& endedAt) {
	mOngoingIds.emplace(conferenceId);
	mRestClient.patch(
	    toApiPath("conferences/" + conferenceId), optional{json{{"ended_at", endedAt}}},
	    [this, id = conferenceId](const auto&, const auto&) { successCallback(id); },
	    [this, id = conferenceId](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + conferenceId + "]",
	    getLogPrefix(__func__) + " request error for id["s + conferenceId + "]");
}

void FlexiStats::conferenceAddParticipantEvent(const string& conferenceId,
                                               const ApiFormattedUri& sipUri,
                                               const ParticipantEvent& participantEvent) {
	if (mOngoingIds.count(conferenceId) != 0) {
		auto patch = [this, conferenceId, sipUri, participantEvent] {
			conferenceAddParticipantEventPatch(conferenceId, sipUri, participantEvent);
		};
		addPatchToWaitingQueue(conferenceId, std::move(patch));
		return;
	}

	conferenceAddParticipantEventPatch(conferenceId, sipUri, participantEvent);
}
void FlexiStats::conferenceAddParticipantEventPatch(const string& conferenceId,
                                                    const ApiFormattedUri& sipUri,
                                                    const ParticipantEvent& participantEvent) {
	mOngoingIds.emplace(conferenceId);
	mRestClient.post(
	    toApiPath("conferences/" + conferenceId + "/participants/" + string(sipUri) + "/events"), participantEvent,
	    [this, id = conferenceId](const auto&, const auto&) { successCallback(id); },
	    [this, id = conferenceId](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + conferenceId + "]",
	    getLogPrefix(__func__) + " request error for id["s + conferenceId + "]");
}

void FlexiStats::conferenceAddParticipantDeviceEvent(const string& conferenceId,
                                                     const ApiFormattedUri& sipUri,
                                                     const string& deviceId,
                                                     const ParticipantDeviceEvent& participantDeviceEvent) {
	if (mOngoingIds.count(conferenceId) != 0) {
		auto patch = [this, conferenceId, sipUri, deviceId, participantDeviceEvent] {
			conferenceAddParticipantDeviceEventPatch(conferenceId, sipUri, deviceId, participantDeviceEvent);
		};
		addPatchToWaitingQueue(conferenceId, std::move(patch));
		return;
	}

	conferenceAddParticipantDeviceEventPatch(conferenceId, sipUri, deviceId, participantDeviceEvent);
}
void FlexiStats::conferenceAddParticipantDeviceEventPatch(const string& conferenceId,
                                                          const ApiFormattedUri& sipUri,
                                                          const string& deviceId,
                                                          const ParticipantDeviceEvent& participantDeviceEvent) {
	mOngoingIds.emplace(conferenceId);
	mRestClient.post(
	    toApiPath("conferences/" + conferenceId + "/participants/" + string(sipUri) + "/devices/" + deviceId +
	              "/events"),
	    participantDeviceEvent, [this, id = conferenceId](const auto&, const auto&) { successCallback(id); },
	    [this, id = conferenceId](const auto&) { errorCallback(id); },
	    getLogPrefix(__func__) + " request successful for id["s + conferenceId + "]",
	    getLogPrefix(__func__) + " request error for id["s + conferenceId + "]");
}

std::string FlexiStats::toApiPath(const string& methodPath) const {
	return mApiPrefix + methodPath;
}