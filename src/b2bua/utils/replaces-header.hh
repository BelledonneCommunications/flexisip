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

#pragma once

#include <memory>
#include <optional>
#include <string>

#include "linphone++/call.hh"

namespace flexisip::b2bua {

class ReplacesHeader {
public:
	~ReplacesHeader() = default;

	static std::optional<ReplacesHeader> fromStr(std::string_view header);

	void update(const std::shared_ptr<linphone::Call>& call);
	std::string str() const;

	const std::string& getCallId() const {
		return mCallId;
	}
	const std::string& getFromTag() const {
		return mFromTag;
	}
	const std::string& getToTag() const {
		return mToTag;
	}

	friend std::ostream& operator<<(std::ostream& strm, const ReplacesHeader& header);

private:
	static constexpr std::string_view mLogPrefix{"ReplacesHeader"};

	ReplacesHeader(std::string_view callId, std::string_view fromTag, std::string_view toTag);

	std::string mCallId{};
	std::string mFromTag{};
	std::string mToTag{};
};

std::ostream& operator<<(std::ostream& strm, const ReplacesHeader& header);

} // namespace flexisip::b2bua