/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/logmanager.hh"
#include "utils/string-utils.hh"

#include "flexisip/push-param.hh"

using namespace std;

namespace flexisip {

bool PushParam::operator==(const PushParam& pp) const {
	return pp.mPrId == mPrId && pp.mParam == mParam;
}

PushParamList::PushParamList(const string& provider, const string& customPrId, const string& customParam)
    : mProvider{provider} {
	if (mProvider == "fcm" || (mProvider.find("apns") != string::npos && customPrId.find("&") == string::npos)) {
		mPushParams.emplace_back(customPrId, customParam);
		return;
	}
	auto splitedPrId = StringUtils::split(customPrId, "&");
	if (splitedPrId.size() != 2) {
		SLOGD << "Bad pn-prid format : " << customPrId;
		return;
	}
	const string remoteParam{StringUtils::split(customParam, ".remote&voip").at(0)};
	const string pushKitParam{StringUtils::split(customParam, ".remote&voip").at(0).append(".voip")};
	if (splitedPrId.at(0).find(":remote") != string::npos) {
		mPushParams.emplace_back(StringUtils::split(splitedPrId.at(0), ":").at(0), remoteParam);
		mPushParams.emplace_back(StringUtils::split(splitedPrId.at(1), ":").at(0), pushKitParam);
	} else {
		mPushParams.emplace_back(StringUtils::split(splitedPrId.at(1), ":").at(0), remoteParam);
		mPushParams.emplace_back(StringUtils::split(splitedPrId.at(0), ":").at(0), pushKitParam);
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
