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

#include "endpoints.hh"

#include <filesystem>

using namespace std;
namespace flexisip::flexiapi::endpoints {

static const filesystem::path kFlexiApiPath{"/api"};
static const filesystem::path kAcccountsApiPath = kFlexiApiPath / "accounts";
// Statistics endpoints
static const filesystem::path kSstatisticsApiPath = kFlexiApiPath / "statistics";
static const filesystem::path kCallsStatsApiPath = kSstatisticsApiPath / "calls";
static const filesystem::path kConfsStatsApiPath = kSstatisticsApiPath / "conferences";
static const filesystem::path kMsgsStatsApiPath = kSstatisticsApiPath / "messages";
// Push notifications
static const filesystem::path kPushNotificationPath = kFlexiApiPath / "push_notification";
// Spaces
static const filesystem::path kSpacesPath = kFlexiApiPath / "spaces";

std::string resolveUri(const ApiFormattedUri& sipUri) {
	return kFlexiApiPath / "resolve" / string{sipUri};
}

std::string accountSearch(const ApiFormattedUri& sipUri) {
	return kAcccountsApiPath / string{sipUri} / "search";
}

std::string voicemailSlotCreation(int accountId) {
	return kAcccountsApiPath / to_string(accountId) / "voicemails";
}

std::string messagesStatistics() {
	return kMsgsStatsApiPath;
}

std::string messagesStatistics(const string& messageId, const ApiFormattedUri& sipUri, const std::string& deviceId) {
	return kMsgsStatsApiPath / messageId / "to" / string(sipUri) / "devices" / deviceId;
}

std::string callsStatistics() {
	return kCallsStatsApiPath;
}

std::string callsStatistics(const std::string& callId) {
	return kCallsStatsApiPath / callId;
}

std::string callsStatistics(const std::string& callId, const std::string& deviceId) {
	return kCallsStatsApiPath / callId / "devices" / deviceId;
}

std::string conferencesStatistics() {
	return kConfsStatsApiPath;
}

std::string conferencesStatistics(const std::string& conferenceId) {
	return kConfsStatsApiPath / conferenceId;
}

std::string conferencesStatistics(const std::string& conferenceId, const ApiFormattedUri& paticipantUri) {
	return kConfsStatsApiPath / conferenceId / "participants" / string(paticipantUri) / "events";
}

std::string conferencesStatistics(const std::string& conferenceId,
                                  const ApiFormattedUri& paticipantUri,
                                  const std::string& deviceId) {
	return kConfsStatsApiPath / conferenceId / "participants" / string(paticipantUri) / "devices" / deviceId / "events";
}

std::string remotePushNotifications() {
	return kPushNotificationPath;
}

std::string spaces() {
	return kSpacesPath;
}

} // namespace flexisip::flexiapi::endpoints