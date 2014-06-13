/*
 * SignalingException.cc
 *
 *  Created on: 6 juin 2014
 *      Author: jehanmonnier
 */

#include <signaling-exception.hh>
#include "belle-sip/belle-sip.h"
namespace flexisip {

SignalingException::SignalingException(int code, list<belle_sip_header_t*> headers) :FlexisipException(),mStatusCode(code),mHeaders(headers) {
	mOffset++;
	for(belle_sip_header_t* header : mHeaders) {
		belle_sip_object_ref(header);
	}
}
SignalingException::SignalingException(int code, belle_sip_header_t* header) :SignalingException(code){
	mHeaders.push_back(header);
	belle_sip_object_ref(header);
	mOffset++;
}
SignalingException::~SignalingException() {
	for(belle_sip_header_t* header : mHeaders) {
		belle_sip_object_unref(header);
	}
}
SignalingException::SignalingException(const SignalingException& other ):mStatusCode(other.mStatusCode) {
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
