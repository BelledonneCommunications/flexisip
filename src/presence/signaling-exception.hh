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

#ifndef SIGNALINGEXCEPTION_HH_
#define SIGNALINGEXCEPTION_HH_

#include "flexisip-exception.hh"
#include <list>
typedef struct _belle_sip_header belle_sip_header_t;

namespace flexisip {

class SignalingException : public FlexisipException {
  public:
	SignalingException(int statusCode, std::list<belle_sip_header_t *> headers = std::list<belle_sip_header_t *>());
	SignalingException(int statusCode, belle_sip_header_t *header);
	SignalingException(const SignalingException &other);
	virtual ~SignalingException() throw();
	int getStatusCode();
	const std::list<belle_sip_header_t *> &getHeaders();
	template <typename T2> SignalingException &operator<<(const T2 &val) {
		FlexisipException::operator<<(val);
		return *this;
	}

  private:
	const int mStatusCode;
	std::list<belle_sip_header_t *> mHeaders;
};

} /* namespace flexisip */
#define SIGNALING_EXCEPTION_1(code, header)                                                                            \
	SignalingException(code, header) << " " << __FILE__ << ":" << __LINE__ << " "
#define SIGNALING_EXCEPTION(code) SIGNALING_EXCEPTION_1(code, NULL)

#endif /* SIGNALINGEXCEPTION_HH_ */
