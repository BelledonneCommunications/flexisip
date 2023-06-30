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

#include <list>

#include "utils/signaling-exception.hh"

typedef struct _belle_sip_header belle_sip_header_t;

namespace flexisip {

class BelleSipSignalingException : public SignalingException {
public:
	BelleSipSignalingException(int statusCode,
	                           std::list<belle_sip_header_t*> headers = std::list<belle_sip_header_t*>());
	BelleSipSignalingException(int statusCode, belle_sip_header_t* header);
	BelleSipSignalingException(const BelleSipSignalingException& other);
	virtual ~BelleSipSignalingException() throw();
	const std::list<belle_sip_header_t*>& getHeaders() const;
	template <typename T2>
	BelleSipSignalingException& operator<<(const T2& val) {
		SignalingException::operator<<(val);
		return *this;
	}

private:
	std::list<belle_sip_header_t*> mHeaders;
};

} /* namespace flexisip */
#define BELLESIP_SIGNALING_EXCEPTION_1(code, header)                                                                   \
	BelleSipSignalingException(code, header) << " " << __FILE__ << ":" << __LINE__ << " "
#define BELLESIP_SIGNALING_EXCEPTION(code) BELLESIP_SIGNALING_EXCEPTION_1(code, NULL)
