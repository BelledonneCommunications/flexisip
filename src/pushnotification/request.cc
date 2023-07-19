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

#include "request.hh"

#include <array>
#include <ctime>
#include <regex>

#include "flexisip/logmanager.hh"

#include "utils/string-utils.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

Request::Request(PushType pType, const std::shared_ptr<const PushInfo>& pInfo) : mPType{pType}, mPInfo{pInfo} {
	const auto& dests = mPInfo->mDestinations;
	if (dests.find(mPType) == dests.cend()) {
		throw UnsupportedPushType(mPType);
	}
}

void Request::setState(State state) noexcept {
	SLOGD << "Request[" << this << "]: switching state from " << mState << " -> " << state;
	mState = state;
}

std::string Request::quoteStringIfNeeded(const std::string& str) const noexcept {
	if (str[0] == '"') {
		return str;
	} else {
		string res;
		res.reserve(str.size() + 2);
		return std::move(res) + "\"" + str + "\"";
	}
}

std::string Request::getPushTimeStamp() const noexcept {
	auto t = time(nullptr);
	struct tm time {};
	gmtime_r(&t, &time);

	string date(20, '\0');
	auto ret = strftime(&date[0], date.size(), "%Y-%m-%d %H:%M:%S", &time);
	if (ret == 0) {
		SLOGE << "Invalid time stamp for push notification PNR: " << this;
	}
	date.resize(ret);
	return date;
}

std::ostream& operator<<(std::ostream& os, Request::State state) noexcept {
#define stateCase(stateEnumName)                                                                                       \
	case Request::State::stateEnumName:                                                                                \
		os << #stateEnumName;                                                                                          \
		break

	switch (state) {
		stateCase(NotSubmitted);
		stateCase(InProgress);
		stateCase(Successful);
		stateCase(Failed);
	}
	return os;

#undef stateCase
}

} // namespace pushnotification
} // namespace flexisip
