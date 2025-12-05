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
#include <queue>
#include <string>
#include <unordered_set>

#include "flexiapi/schemas/call/call.hh"
#include "flexiapi/schemas/conference/conference.hh"
#include "flexiapi/schemas/conference/participant-device-event.hh"
#include "flexiapi/schemas/conference/participant-event.hh"
#include "flexiapi/schemas/message/message.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip::flexiapi {

class FlexiStats {
public:
	FlexiStats(sofiasip::SuRoot& root,
	           const std::string& host,
	           const std::string& port,
	           const std::string& apiPrefix,
	           const std::string& token);

	/********** MESSAGES **********/
	void postMessage(const Message& message);
	void notifyMessageDeviceResponse(const std::string& messageId,
	                                 const ApiFormattedUri& sipUri,
	                                 const std::string& deviceId,
	                                 const MessageDeviceResponse& messageDeviceResponse);

	/********** CALLS **********/
	void postCall(const Call& call);
	void updateCallDeviceState(const std::string& callId,
	                           const std::string& deviceId,
	                           const CallDeviceState& callDeviceState);
	void updateCallState(const std::string& callId, const ISO8601Date& endedAt);

	/********** CONFERENCES **********/
	void postConference(const Conference& conference);
	void notifyConferenceEnded(const std::string& conferenceId, const ISO8601Date& endedAt);
	void conferenceAddParticipantEvent(const std::string& conferenceId,
	                                   const ApiFormattedUri& sipUri,
	                                   const ParticipantEvent& participantEvent);
	void conferenceAddParticipantDeviceEvent(const std::string& conferenceId,
	                                         const ApiFormattedUri& sipUri,
	                                         const std::string& deviceId,
	                                         const ParticipantDeviceEvent& participantDeviceEvent);

private:
	static constexpr std::string_view mLogPrefix{"FlexiStats"};

	std::string toApiPath(const std::string& methodPath) const;
	static std::string getLogPrefix(const std::string& func) {
		return std::string{mLogPrefix} + "::" + func;
	}

	/********** MESSAGES **********/
	void notifyMessageDeviceResponsePatch(const std::string& messageId,
	                                      const ApiFormattedUri& sipUri,
	                                      const std::string& deviceId,
	                                      const MessageDeviceResponse& messageDeviceResponse);

	/********** CALLS **********/
	void updateCallDeviceStatePatch(const std::string& callId,
	                                const std::string& deviceId,
	                                const CallDeviceState& callDeviceState);
	void updateCallStatePatch(const std::string& callId, const ISO8601Date& endedAt);

	/********** CONFERENCES **********/
	void notifyConferenceEndedPatch(const std::string& conferenceId, const ISO8601Date& endedAt);
	void conferenceAddParticipantEventPatch(const std::string& conferenceId,
	                                        const ApiFormattedUri& sipUri,
	                                        const ParticipantEvent& participantEvent);
	void conferenceAddParticipantDeviceEventPatch(const std::string& conferenceId,
	                                              const ApiFormattedUri& sipUri,
	                                              const std::string& deviceId,
	                                              const ParticipantDeviceEvent& participantDeviceEvent);

	/**
	 * Callback to call on request success. Sends the next patches if any are waiting for this ID.
	 */
	void successCallback(const std::string& id);
	/**
	 * Callback to call on request error. Next patches are dropped if any are waiting for this ID.
	 */
	void errorCallback(const std::string& id);
	/**
	 * Adds a patch to the waiting queue for processing. Queues are different for each resource (identified by id).
	 */
	void addPatchToWaitingQueue(const std::string& id, std::function<void()>&& patch);

	std::unordered_map<std::string, std::queue<std::function<void()>>> mWaitingPatches;
	std::unordered_set<std::string> mOngoingIds;

	RestClient mRestClient;
	std::string mApiPrefix;
};

} // namespace flexisip::flexiapi