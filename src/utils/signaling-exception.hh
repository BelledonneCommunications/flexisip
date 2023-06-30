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

#pragma once

#include <flexisip/flexisip-exception.hh>

namespace flexisip {

/**
 * @brief This exception inherits \ref FlexisipException and allows a SIP error code to be carried along.
 *
 * @param statusCode the status code of the SIP message that we would send back after a message triggered this
 * exception.
 */
class SignalingException : public FlexisipException {
public:
	SignalingException(int statusCode, const std::string& reason) : mStatusCode(statusCode), mReason(reason) {
	}
	SignalingException(int statusCode) : mStatusCode(statusCode), mReason("Internal Error") {
	}
	SignalingException(const SignalingException& other)
	    : FlexisipException(other), mStatusCode(other.mStatusCode), mReason(other.mReason) {
	}

	virtual ~SignalingException() throw() {
	}

	int getStatusCode() const {
		return mStatusCode;
	}
	std::string getReason() const {
		return mReason;
	}

	template <typename T2>
	SignalingException& operator<<(const T2& val) {
		FlexisipException::operator<<(val);
		return *this;
	}

private:
	const int mStatusCode;
	std::string mReason;
};

#define SIGNALING_EXCEPTION(code) SignalingException(code) << " " << __FILE__ << ":" << __LINE__ << " "

} // namespace flexisip