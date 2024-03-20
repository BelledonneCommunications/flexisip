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

#include <stdexcept>

#include "flexisip/logmanager.hh"

#include "utils/string-utils.hh"

#include "push-notification-exceptions.hh"
#include "push-param.hh"

using namespace std;

namespace flexisip {

using namespace pushnotification;

PushParam::PushParam(const string& prId, const string& param) : mPrId{prId}, mParam{param} {
	if (isInvalid()) {
		throw InvalidPushParameters{"prid[" + prId + "] and param[" + param + "] cannot be empty."};
	}
}

bool PushParam::operator==(const PushParam& pp) const {
	return pp.mPrId == mPrId && pp.mParam == mParam;
}

PushParamList::PushParamList(const string& provider,
                             const string& customPrId,
                             const string& customParam,
                             bool isLegacyContactParams) {
	if (isLegacyContactParams) {
		constructFromLegacyContactParameters(provider, customPrId, customParam);
	} else {
		constructFromContactParameters(provider, customPrId, customParam);
	}
}

void PushParamList::constructFromLegacyContactParameters(const string& pnType,
                                                         const string& pnTok,
                                                         const string& appId) {
	string provider{};
	if (pnType == "firebase" || pnType == "google") {
		provider = "fcm";
		constructFromContactParameters(provider, pnTok, appId);
		return;
	} else {
		string customParam{appId};
		size_t prodPrefixPos = string::npos;
		if ((prodPrefixPos = appId.find(".prod")) != string::npos) {
			provider = "apns";
			customParam = customParam.substr(0, prodPrefixPos);
		} else {
			provider = "apns.dev";
			customParam = customParam.substr(0, appId.find(".dev"));
		}
		customParam = "ABCD1234." + customParam;
		constructFromContactParameters(provider, pnTok, customParam);
	}
}

void PushParamList::constructFromContactParameters(const string& provider,
                                                   const string& customPrId,
                                                   const string& customParam) {
	mProvider = provider;
	if (mProvider == "fcm" || (StringUtils::startsWith(mProvider, "apns") && customPrId.find("&") == string::npos)) {
		mPushParams.emplace_back(customPrId, customParam);
		return;
	}
	auto splitPrId = StringUtils::split(customPrId, "&");
	if (splitPrId.size() != 2 ||
	    any_of(splitPrId.cbegin(), splitPrId.cend(), [](const auto& prId) { return prId.empty(); })) {
		SLOGD << "Bad pn-prid format : " << customPrId;
		return;
	}

	const auto lastDotIndex = customParam.find_last_of('.');
	if (lastDotIndex == string::npos) {
		SLOGD << "Bad pn-param format (no dot) : " << customParam;
		return;
	}
	const auto paramSuffix = customParam.substr(lastDotIndex + 1);
	if ("remote&voip" == paramSuffix || "voip&remote" == paramSuffix) {
		const auto remoteParam = customParam.substr(0, lastDotIndex);
		const auto pushKitParam = remoteParam + ".voip";
		try {
			if (splitPrId.at(0).find(":remote") != string::npos) {
				mPushParams.emplace_back(StringUtils::split(splitPrId.at(0), ":").at(0), remoteParam);
				mPushParams.emplace_back(StringUtils::split(splitPrId.at(1), ":").at(0), pushKitParam);
			} else {
				mPushParams.emplace_back(StringUtils::split(splitPrId.at(1), ":").at(0), remoteParam);
				mPushParams.emplace_back(StringUtils::split(splitPrId.at(0), ":").at(0), pushKitParam);
			}
		} catch (const PushNotificationException& exception) {
			SLOGD << exception.what() << " pn-prid[" << customPrId << "] pn-param[" << customParam << "]";
			mPushParams.clear();
		}
	} else {
		SLOGD << "Bad pn-param format : " << customParam;
		return;
	}
}

bool PushParamList::operator==(const PushParamList& ppl) const {
	if (mProvider.empty() || mProvider != ppl.mProvider) {
		return false;
	}
	for (const auto& pp : mPushParams) {
		if (any_of(ppl.mPushParams.begin(), ppl.mPushParams.end(), [&pp](const auto& pp2) { return pp == pp2; })) {
			return true;
		}
	}
	return false;
}

ostream& operator<<(ostream& os, const PushParam& pushParam) noexcept {
	os << "PushParam[" << pushParam.getPrId() << ", " << pushParam.getParam() << ']' << endl;
	return os;
}

ostream& operator<<(ostream& os, const PushParamList& pushParamList) noexcept {
	os << "PushParamList[" << pushParamList.getProvider() << ", "
	   << StringUtils::toString(pushParamList.getPushParams()) << ']' << endl;
	return os;
}

} // namespace flexisip
