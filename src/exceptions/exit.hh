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

#pragma once

#include <exception>
#include <string>
#include <string_view>

namespace flexisip {

/*
 * Report an event that requires the program to be stopped.
 * The cause may be an error or normal program execution.
 */
class Exit : public std::runtime_error {
public:
	explicit Exit(int code) : std::runtime_error{""}, mCode(code) {
	}
	template <typename... Args>
	explicit Exit(int code, Args... args) : std::runtime_error{std::forward<Args>(args)...}, mCode(code) {
	}

	int code() const {
		return mCode;
	}

private:
	int mCode;
};

} // namespace flexisip