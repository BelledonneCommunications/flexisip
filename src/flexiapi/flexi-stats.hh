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

#pragma once

#include "flexiapi/schemas/call/call.hh"
#include "flexiapi/schemas/conference/conference.hh"
#include "flexiapi/schemas/conference/participant-device-event.hh"
#include "flexiapi/schemas/conference/participant-event.hh"
#include "flexiapi/schemas/message/message.hh"
#include "utils/transport/http/rest-client.hh"

namespace flexisip {
namespace flexiapi {

class FlexiStats {
public:
	FlexiStats(sofiasip::SuRoot& root, const std::string& host, const std::string& port, const std::string& token);

	/********** MESSAGES **********/
	void postMessage(const Message& message);
	void notifyMessageDeviceResponse(const std::string& messageId,
	                                 const ApiFormattedUri& sipUri,
	                                 const std::string deviceId,
	                                 const MessageDeviceResponse& messageDeviceResponse);

	/********** CALLS **********/
	void postCall(const Call& call);
	void updateCallDeviceState(const std::string& callId, const std::string& deviceId, const CallDeviceState& call);
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
	RestClient mRestClient;
};

} // namespace flexiapi
} // namespace flexisip