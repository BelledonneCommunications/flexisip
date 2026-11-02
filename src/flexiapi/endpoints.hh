/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "schemas/api-formatted-uri.hh"

namespace flexisip::flexiapi::endpoints {

// Accounts
std::string resolveUri(const ApiFormattedUri& sipUri);
std::string accountSearch(const ApiFormattedUri& sipUri);
std::string voicemailSlotCreation(int accountId);
// Statistics
std::string messagesStatistics();
std::string
messagesStatistics(const std::string& messageId, const ApiFormattedUri& sipUri, const std::string& deviceId);
std::string callsStatistics();
std::string callsStatistics(const std::string& callId);
std::string callsStatistics(const std::string& callId, const std::string& deviceId);
std::string conferencesStatistics();
std::string conferencesStatistics(const std::string& conferenceId);
std::string conferencesStatistics(const std::string& conferenceId, const ApiFormattedUri& paticipantUri);
std::string conferencesStatistics(const std::string& conferenceId,
                                  const ApiFormattedUri& paticipantUri,
                                  const std::string& deviceId);
// Push Notifications
std::string remotePushNotifications();
// Spaces
std::string spaces();

} // namespace flexisip::flexiapi::endpoints
