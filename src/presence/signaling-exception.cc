/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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
#include "signaling-exception.hh"
#include "belle-sip/belle-sip.h"
namespace flexisip {

SignalingException::SignalingException(int code, list<belle_sip_header_t*> headers) :FlexisipException(),mStatusCode(code),mHeaders(headers) {
	mOffset++;
	for(belle_sip_header_t* header : mHeaders) {
		belle_sip_object_ref(header);
	}
}
SignalingException::SignalingException(int code, belle_sip_header_t* header) :SignalingException(code){
	if (header) {
		mHeaders.push_back(header);
		belle_sip_object_ref(header);
	}
	mOffset++;
}
SignalingException::~SignalingException() {
	for(belle_sip_header_t* header : mHeaders) {
		belle_sip_object_unref(header);
	}
}
SignalingException::SignalingException(const SignalingException& other ): FlexisipException(other),mStatusCode(other.mStatusCode) {
	for (belle_sip_header_t* header : other.mHeaders) {
		mHeaders.push_back(header);
		belle_sip_object_ref(header);
	}
}
int SignalingException::getStatusCode() {
	return mStatusCode;
}
const list<belle_sip_header_t*>& SignalingException::getHeaders() {
	return mHeaders;
}
} /* namespace flexisip */
