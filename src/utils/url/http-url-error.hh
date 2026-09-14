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

#include <stdexcept>

namespace flexisip {

class HttpUrlError : public std::runtime_error {
public:
	explicit HttpUrlError(const std::string_view statusPhrase) : HttpUrlError(statusPhrase, "") {}
	HttpUrlError(const std::string_view statusPhrase, const std::string_view additionalMsg)
	    : std::runtime_error(statusPhrase.data()), mMsg(statusPhrase) {
		if (!additionalMsg.empty()) mMsg += std::string(": ") + additionalMsg.data();
	}
	const char* what() const noexcept override {
		return mMsg.data();
	}

private:
	std::string mMsg;
};

} // namespace flexisip