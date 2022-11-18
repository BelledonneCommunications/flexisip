/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <string.h>

#include <bctoolbox/exception.hh>

namespace flexisip {

/**
 * @brief This exception inherits \ref BctoolboxException.
 *
 *
 */
class FlexisipException : public BctbxException {
public:
	FlexisipException() = default;
	FlexisipException(const std::string &message): BctbxException(message) {}
	FlexisipException(const char *message): BctbxException(message) {}
	virtual ~FlexisipException() throw() {}
	FlexisipException(const FlexisipException &other): BctbxException(other) {}
	
	template <typename T2> FlexisipException &operator<<(const T2 &val) {
		BctbxException::operator<<(val);
		return *this;
	}
};

#define FLEXISIP_EXCEPTION FlexisipException() << " " << __FILE__ << ":" << __LINE__ << " "

}