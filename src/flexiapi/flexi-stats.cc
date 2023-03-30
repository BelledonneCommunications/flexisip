/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "flexi-stats.hh"

using namespace std;
using namespace flexisip;
using namespace flexiapi;
using namespace nlohmann;

FlexiStats::FlexiStats(sofiasip::SuRoot& root,
                       const std::string& host,
                       const std::string& port,
                       const std::string& token)
    : mRestClient(Http2Client::make(root, host, port),
                  HttpHeaders{
                      {":authority"s, host + ":" + port},
                      {"x-api-key"s, token},
                  }) {
}

void FlexiStats::postMessage(const Message& message) {
	mRestClient.post("/api/stats/messages"s, message,
	                 "FlexiStats::postMessage request successful for id["s + message.id + "]",
	                 "FlexiStats::postMessage request error for id["s + message.id + "]");
}
void FlexiStats::notifyMessageDeviceResponse(const string& messageId,
                                             const ApiFormattedUri& sipUri,
                                             const std::string deviceId,
                                             const MessageDeviceResponse& messageDeviceResponse) {
	mRestClient.patch("/api/stats/messages/"s + messageId + "/to/" + string(sipUri) + "/devices/" + deviceId,
	                  messageDeviceResponse,
	                  "FlexiStats::notifyMessageDeviceResponse request successful for id["s + messageId + "]",
	                  "FlexiStats::notifyMessageDeviceResponse request error for id["s + messageId + "]");
}

void FlexiStats::postCall(const Call& call) {
	mRestClient.post("/api/stats/calls"s, call, "FlexiStats::postCall request successful for id["s + call.id + "]",
	                 "FlexiStats::postCall request error for id["s + call.id + "]");
}
void FlexiStats::updateCallDeviceState(const string& callId,
                                       const string& deviceId,
                                       const CallDeviceState& callDeviceState) {
	mRestClient.patch("/api/stats/calls/"s + callId + "/devices/" + deviceId, callDeviceState,
	                  "FlexiStats::updateCallDeviceState request successful for id["s + callId + "]",
	                  "FlexiStats::updateCallDeviceState request error for id["s + callId + "]");
}
void FlexiStats::updateCallState(const string& callId, const ISO8601Date& endedAt) {
	mRestClient.patch("/api/stats/calls/"s + callId, optional<json>{json{{"ended_at", endedAt}}},
	                  "FlexiStats::updateCallState request successful for id["s + callId + "]",
	                  "FlexiStats::updateCallState request error for id["s + callId + "]");
}

void FlexiStats::postConference(const Conference& conference) {
	mRestClient.post("/api/stats/conferences"s, conference,
	                 "FlexiStats::postConference request successful for id["s + conference.id + "]",
	                 "FlexiStats::postConference request error for id["s + conference.id + "]");
}
void FlexiStats::notifyConferenceEnded(const string& conferenceId, const ISO8601Date& endedAt) {
	mRestClient.patch("/api/stats/conferences/"s + conferenceId, optional<json>{json{{"ended_at", endedAt}}},
	                  "FlexiStats::notifyConferenceEnded request successful for id["s + conferenceId + "]",
	                  "FlexiStats::notifyConferenceEnded request error for id["s + conferenceId + "]");
}
void FlexiStats::conferenceAddParticipantEvent(const string& conferenceId,
                                               const ApiFormattedUri& sipUri,
                                               const ParticipantEvent& participantEvent) {
	mRestClient.post("/api/stats/conferences/"s + conferenceId + "/participants/" + string(sipUri) + "/events",
	                 participantEvent,
	                 "FlexiStats::conferenceAddParticipantEvent request successful for id["s + conferenceId + "]",
	                 "FlexiStats::conferenceAddParticipantEvent request error for id["s + conferenceId + "]");
}
void FlexiStats::conferenceAddParticipantDeviceEvent(const string& conferenceId,
                                                     const ApiFormattedUri& sipUri,
                                                     const string& deviceId,
                                                     const ParticipantDeviceEvent& participantDeviceEvent) {
	mRestClient.post("/api/stats/conferences/"s + conferenceId + "/participants/" + string(sipUri) + "/devices/" +
	                     deviceId + "/events",
	                 participantDeviceEvent,
	                 "FlexiStats::conferenceAddParticipantDeviceEvent request successful for id["s + conferenceId + "]",
	                 "FlexiStats::conferenceAddParticipantDeviceEvent request error for id["s + conferenceId + "]");
}
