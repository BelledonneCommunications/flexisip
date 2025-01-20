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

#include <string>

namespace flexisip {

namespace utils {

/**
 * std::string wrapper class.
 *
 * A Utf8String is guaranteed by/at construction to contain only valid UTF8 data. Invalid code units present in the
 * source are replaced. (by U+FFFD '�')
 */
class Utf8String {
public:
	Utf8String(const std::string&);

	operator const std::string&() const {
		return mData;
	}

	const std::string& asString() const {
		return mData;
	}

private:
	std::string mData;
};

} // namespace utils

} // namespace flexisip