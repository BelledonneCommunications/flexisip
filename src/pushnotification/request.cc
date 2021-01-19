/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctime>
#include <regex>
#include <flexisip/logmanager.hh>
#include "utils/string-utils.hh"
#include "request.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

/* Apple pn-provider may be 'apns' or 'apns.dev' */
static const std::regex sApplePnProviderRegex("apns|apns\\.dev");

/*
   pn-param:
   * all the characters before the first point are taken as the team ID;
   * all the characters between the first and the last point are taken as the bundle ID
	 and may contains points;
   * all the characters after the last point are taken as the service type. It may be
	 'voip' or 'remote' or 'voip&remote' if the application needs the two kinds of
	 push notification.
*/
static const std::regex sPnParamRegex("([^.]+)\\.(.+)\\.((?:voip|remote|&)+)");

/*
   Regex to use for extracting information from 'pn-prid' parameter when only one token has been
   given by the user agent. All the characters or all the characters before ':' are taken as
   the token. Characters after ':' must be 'voip' or 'remote'. Column character isn't authorized
   in the token.
*/
static const std::regex sPnPridOneTokenRegex("([^:]+)(?::(voip|remote))?");

/*
   Regex to use for extracting information from 'pn-prid' parameter when several tokens have been
   given by the user agent. 'pn-prid' value must be formated as '<token>:<service>' where
   <token> may be contains any characters except ':' and <service> is equal to 'remote' or 'voip'.
*/
static const std::regex sPnPridMultipleTokensRegex("([^:]+):(voip|remote)");


string toString(ApplePushType type) noexcept {
	switch (type) {
		case ApplePushType::Unknown: return "Unknown";
		case ApplePushType::Pushkit: return "PushKit";
		case ApplePushType::RemoteBasic: return "RemoteBasic";
		case ApplePushType::RemoteWithMutableContent: return "RemoteWithMutableContent";
		case ApplePushType::Background: return "BackGround";
	};
	return "<invalid>";
}

void PushInfo::readRFC8599PushParams(const RFC8599PushParams &params) {
	smatch match;
	
	if (params.pnProvider == "fcm") { // firebase
		mType = "firebase";
		mDeviceToken = params.pnPrid;
		mAppId = params.pnParam;
	} else if (regex_match(params.pnProvider, match, pushnotification::sApplePnProviderRegex)) { // apple
		mType = "apple";
		string deviceToken;
		string bundleId;
		vector<string> servicesAvailable;
		bool isDev = (params.pnProvider == "apns.dev");
		string requiredService;

		if (regex_match(params.pnParam, match, sPnParamRegex)) {
			mTeamId = match[1].str();
			bundleId = match[2].str();
			servicesAvailable = StringUtils::split(match[3].str(), "&");
		} else {
			throw runtime_error("pn-param invalid syntax");
		}

		auto it = find(servicesAvailable.begin(), servicesAvailable.end(), "voip");
		if (mEvent == pushnotification::PushInfo::Event::Message || it == servicesAvailable.end()) {
			requiredService = "remote";
			mApplePushType = pushnotification::ApplePushType::RemoteWithMutableContent;
		} else {
			requiredService = "voip";
			mApplePushType = pushnotification::ApplePushType::Pushkit;
		}

		if (servicesAvailable.cend() == find(servicesAvailable.cbegin(), servicesAvailable.cend(), requiredService)) {
			throw runtime_error(string("pn-param does not define required service: " + requiredService));
		}

		if (!params.pnPrid.empty()) {
			const auto tokenList = StringUtils::split(params.pnPrid, "&");
			for (const auto &tokenAndService : tokenList) {
				if (tokenList.size() == 1) {
					if (regex_match(tokenAndService, match, sPnPridOneTokenRegex)) {
						if (match.size() == 2) {
							deviceToken = match[1].str();
						} else {
							if (match[2].str() == requiredService) {
								deviceToken = match[1].str();
							}
						}
					} else {
						throw runtime_error("pn-prid invalid syntax");
					}
				} else {
					if (regex_match(tokenAndService, match, sPnPridMultipleTokensRegex)) {
						if (match[2].str() == requiredService) {
							deviceToken = match[1].str();
						}
					} else {
						throw runtime_error("pn-prid invalid syntax");
					}
				}
			}
		}

		if (deviceToken.empty()) {
			throw runtime_error(string("pn-prid no token provided for required service: " + requiredService));
		}

		mDeviceToken = deviceToken;
		mAppId = bundleId + (mApplePushType == pushnotification::ApplePushType::Pushkit ? ".voip" : "") + (isDev ? ".dev" : ".prod");
	} else {
		throw runtime_error(string("pn-provider unsupported value: " + params.pnProvider));
	}
}

string Request::quoteStringIfNeeded(const string &str) const noexcept {
	if (str[0] == '"') {
		return str;
	} else {
		string res;
		res.reserve(str.size() + 2);
		return move(res) + "\"" + str + "\"";
	}
}

string Request::getPushTimeStamp() const noexcept {
	time_t t = time(nullptr);
	struct tm time;
	gmtime_r(&t, &time);
	char date[20] = {0};
	size_t ret = strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &time);
	if (ret == 0)
		SLOGE << "Invalid time stamp for push notification PNR: " << this;

	return string(date);
}


} // end of pushnotification namespace
} // end of flexisip namespace
