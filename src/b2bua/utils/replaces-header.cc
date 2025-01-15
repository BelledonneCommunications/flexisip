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

#include "replaces-header.hh"

#include "b2bua/b2bua-server.hh"
#include "utils/string-utils.hh"

using namespace std;

namespace flexisip::b2bua {

ReplacesHeader::ReplacesHeader(std::string_view callId, std::string_view fromTag, std::string_view toTag)
    : mCallId{callId}, mFromTag{fromTag}, mToTag{toTag} {
}

std::optional<ReplacesHeader> ReplacesHeader::fromStr(std::string_view header) {
	if (header.empty()) return nullopt;

	const auto [callId, tags] = *string_utils::splitOnce(header, ";");
	const auto fromToTags = string_utils::parseKeyValue(string{tags}, ';', '=');
	try {
		const auto& fromTag = fromToTags.at("from-tag");
		const auto& toTag = fromToTags.at("to-tag");
		return ReplacesHeader{callId, fromTag, toTag};
	} catch (const out_of_range& exception) {
		LOGD_CTX(kLogPrefix) << "Failed to extract tags from header (" << header << ")";
	}
	return nullopt;
}

void ReplacesHeader::update(const shared_ptr<linphone::Call>& call) {
	mCallId = call->getCallLog()->getCallId();
	if (call->getDir() == linphone::Call::Dir::Outgoing) {
		mFromTag = call->getLocalTag();
		mToTag = call->getRemoteTag();
	} else {
		mFromTag = call->getRemoteTag();
		mToTag = call->getLocalTag();
	}
}

std::string ReplacesHeader::str() const {
	return mCallId + ";from-tag=" + mFromTag + ";to-tag=" + mToTag;
}

std::ostream& operator<<(std::ostream& strm, const ReplacesHeader& header) {
	strm << "{callId: " << header.mCallId << ", from-tag: " << header.mFromTag << ", to-tag: " << header.mToTag << "}";
	return strm;
}

} // namespace flexisip::b2bua