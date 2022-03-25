/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <regex>

#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

#include "rfc8599-push-params.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

void RFC8599PushParams::setFromPushParams(const std::string& pnProvider,
                                          const std::string& pnParam,
                                          const std::string& pnPrid) {
	mProvider = pnProvider;
	mParam = pnParam;
	mPrid = pnPrid;
}

void RFC8599PushParams::setFromLegacyParams(const std::string& pnType,
                                            const std::string& pnAppId,
                                            const std::string& pnTok) {
	if (pnType == "apple") {
		mProvider = StringUtils::endsWith(pnAppId, ".dev") ? "apns.dev" : "apns";
		mParam = string{"ABCD1234."} + pnAppId.substr(0, pnAppId.rfind('.'));
		mPrid = pnTok;
	} else if (pnType == "android" || pnType == "firebase") {
		mProvider = "fcm";
		mParam = pnAppId;
		mPrid = pnTok;
	} else { // wp, wp10 and other.
		mProvider = pnType;
		mParam = pnAppId;
		mPrid = pnTok;
	}
}

std::set<PushType> RFC8599PushParams::getSupportedPNTypes() const noexcept {
	if (mProvider == "apns" || mProvider == "apns.dev") {
		if (StringUtils::endsWith(mParam, ".voip")) {
			return {PushType::VoIP};
		} else {
			return {PushType::Background, PushType::Message};
		}
	} else if (mProvider == "fcm") {
		return {PushType::Background};
	} else if (mProvider == "wp" || mProvider == "wp10") {
		return {PushType::Message, PushType::VoIP};
	} else {
		return {};
	}
}

RFC8599PushParams::ParsingResult RFC8599PushParams::parsePushParams(const std::string& pnProvider,
                                                                    const std::string& pnParam,
                                                                    const std::string& pnPrid) {
	RFC8599PushParams::ParsingResult res{};
	constexpr auto errPrefix = "Invalid RFC8599 push parameters: ";

	smatch match{};
	map<string, std::shared_ptr<RFC8599PushParams>> servicesAvailable{};
	if (regex_match(pnProvider, match, sApplePnProviderRegex)) { // apple
		if (regex_match(pnParam, match, sPnParamRegex)) {
			auto teamId = match[1].str();
			auto bundleId = match[2].str();
			for (const auto& service : StringUtils::split(match[3].str(), "&")) {
				ostringstream param{};
				param << teamId << "." << bundleId << (service == "voip" ? ".voip" : "");
				servicesAvailable[service] = make_shared<RFC8599PushParams>(pnProvider, param.str(), "");
			}
		} else if (regex_match(pnParam, match, sPnParamNoServiceRegex)) {
			auto teamId = match[1].str();
			auto bundleId = match[2].str();
			// if "remote" or "voip" services are not specified, we assume that the service type is "remote"
			ostringstream param{};
			param << teamId << "." << bundleId;
			servicesAvailable["remote"] = make_shared<RFC8599PushParams>(pnProvider, param.str(), "");
		} else {
			throw runtime_error{string{errPrefix} + "pn-param invalid syntax"};
		}

		if (pnPrid.empty()) {
			throw runtime_error{string{errPrefix} + "pn-prid is empty"};
		}

		const auto tokenList = StringUtils::split(pnPrid, "&");
		if (tokenList.size() != servicesAvailable.size()) {
			ostringstream msg{};
			msg << errPrefix << "pn-param declares " << servicesAvailable.size() << " service(s), whereas there is/are "
			    << tokenList.size() << " token(s) in pn-prid";
			throw runtime_error{msg.str()};
		}

		for (const auto& tokenAndService : tokenList) {
			const auto& re = tokenList.size() == 1 ? sPnPridOneTokenRegex : sPnPridMultipleTokensRegex;
			if (!regex_match(tokenAndService, match, re)) {
				throw runtime_error{string{errPrefix} + "pn-prid invalid syntax"};
			}

			auto service = match[2].str();

			// If ":remote" or ":voip" was not specified, we assume that the token matches the available service
			auto pushParams =
			    tokenList.size() == 1 && service.empty() ? servicesAvailable.begin() : servicesAvailable.find(service);
			if (pushParams == servicesAvailable.end()) {
				throw runtime_error{string{errPrefix} + "service mismatch between pn-param and pn-prid"};
			}

			pushParams->second->mPrid = match[1].str();
		}

		for (const auto& kv : servicesAvailable) {
			const auto& dest = kv.second;
			for (auto pnType : dest->getSupportedPNTypes()) {
				res.emplace(pnType, dest);
			}
		}

	} else {
		auto dest = make_shared<RFC8599PushParams>(pnProvider, pnParam, pnPrid);
		for (const auto& pnType : dest->getSupportedPNTypes()) {
			res.emplace(pnType, dest);
		}
	}
	return res;
}

RFC8599PushParams::ParsingResult RFC8599PushParams::parsePushParams(const char* params) {
	const string errPrefix{"Invalid RFC8599 push parameters in Request-URI: "};
	auto pnProvider = UriUtils::getParamValue(params, "pn-provider");
	if (pnProvider.empty()) {
		throw runtime_error{errPrefix + "no pn-provider"};
	}
	auto pnPrid = UriUtils::getParamValue(params, "pn-prid");
	if (pnPrid.empty()) {
		throw runtime_error{errPrefix + "no pn-prid"};
	}
	auto pnParam = UriUtils::getParamValue(params, "pn-param");
	if (pnParam.empty()) {
		throw runtime_error{errPrefix + "no pn-prid"};
	}
	return RFC8599PushParams::parsePushParams(pnProvider, pnParam, pnPrid);
}

RFC8599PushParams::ParsingResult RFC8599PushParams::parseLegacyPushParams(const char* params) {
	using namespace pushnotification;

	const string errPrefix{"Invalid legacy push parameters in Request-URI: "};

	auto pnType = UriUtils::getParamValue(params, "pn-type");
	if (pnType.empty()) {
		throw runtime_error{errPrefix + "no pn-type"};
	}
	auto appId = UriUtils::getParamValue(params, "app-id");
	if (appId.empty()) {
		throw runtime_error{errPrefix + "no app-id"};
	}
	auto pnTok = UriUtils::getParamValue(params, "pn-tok");
	if (pnTok.empty()) {
		throw runtime_error{errPrefix + "no pn-tok"};
	}

	auto dest = make_shared<RFC8599PushParams>();
	dest->setFromLegacyParams(pnType, appId, pnTok);

	RFC8599PushParams::ParsingResult res{};
	for (auto pnType : dest->getSupportedPNTypes()) {
		res.emplace(pnType, dest);
	}
	return res;
}

/* Apple pn-provider may be 'apns' or 'apns.dev' */
const std::regex RFC8599PushParams::sApplePnProviderRegex("apns|apns\\.dev");

/*
   pn-param:
   * all the characters before the first point are taken as the team ID;
   * all the characters between the first and the last point are taken as the bundle ID
     and may contains points;
   * all the characters after the last point are taken as the service type. It may be
     'voip' or 'remote' or 'voip&remote' if the application needs the two kinds of
     push notification.
*/
const std::regex RFC8599PushParams::sPnParamRegex("([^.]+)\\.(.+)\\.((?:voip|remote|&)+)");
const std::regex RFC8599PushParams::sPnParamNoServiceRegex(
    "([^.]+)\\.(.+)"); // If no service type is specified, we assume that the service type is "remote"

/*
   Regex to use for extracting information from 'pn-prid' parameter when only one token has been
   given by the user agent. All the characters or all the characters before ':' are taken as
   the token. Characters after ':' must be 'voip' or 'remote'. Column character isn't authorized
   in the token. "remote" is used by default if nothing is specified.
*/
const std::regex RFC8599PushParams::sPnPridOneTokenRegex("([^:]+)(?::(voip|remote))?");

/*
   Regex to use for extracting information from 'pn-prid' parameter when several tokens have been
   given by the user agent. 'pn-prid' value must be formatted as '<token>:<service>' where
   <token> may be contains any characters except ':' and <service> is equal to 'remote' or 'voip'.
*/
const std::regex RFC8599PushParams::sPnPridMultipleTokensRegex("([^:]+):(voip|remote)");

} // namespace pushnotification
} // namespace flexisip
