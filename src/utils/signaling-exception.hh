/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2014  Belledonne Communications SARL.

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

#ifndef SIGNALING_EXCEPTION_HH_
#define SIGNALING_EXCEPTION_HH_

#include "flexisip-exception.hh"

namespace flexisip {

/**
 * @brief This exception inherits \ref FlexisipException and allows a SIP error code to be carried along.
 * 
 * @param statusCode the status code of the SIP message that we would send back after a message triggered this exception.
 */
class SignalingException : public FlexisipException {
  public:
	SignalingException(int statusCode) : mStatusCode(statusCode) {}
	SignalingException(const SignalingException &other) : mStatusCode(other.mStatusCode) {}
	
	virtual ~SignalingException() {}
	
	int getStatusCode() { return mStatusCode; }
	
	template <typename T2> SignalingException &operator<<(const T2 &val) {
		FlexisipException::operator<<(val);
		return *this;
	}

  private:
	const int mStatusCode;
};

} /* namespace flexisip */
#define SIGNALING_EXCEPTION(code) SignalingException(code) << " " << __FILE__ << ":" << __LINE__ << " "

#endif /* SIGNALING_EXCEPTION_HH_ */
