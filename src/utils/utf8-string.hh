/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
