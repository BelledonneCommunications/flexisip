/*
 * SignalingException.hh
 *
 *  Created on: 6 juin 2014
 *      Author: jehanmonnier
 */

#ifndef SIGNALINGEXCEPTION_HH_
#define SIGNALINGEXCEPTION_HH_

#include "flexisip-exception.hh"
#include <list>
typedef struct _belle_sip_header belle_sip_header_t;

namespace flexisip {

class SignalingException: public FlexisipException {
public:
	SignalingException(int statusCode, std::list<belle_sip_header_t*> headers=std::list<belle_sip_header_t*>());
	SignalingException(int statusCode,belle_sip_header_t* header);
	SignalingException(const SignalingException& other );
	virtual ~SignalingException();
	int getStatusCode();
	const std::list<belle_sip_header_t*>& getHeaders();
private:
	const int mStatusCode;
	std::list<belle_sip_header_t*> mHeaders;
};

} /* namespace flexisip */
#define SIGNALING_EXCEPTION_1(code,header) SignalingException(code,header) << " " << __FILE__ << ":"<< __LINE__ << " "
#define SIGNALING_EXCEPTION(code) SIGNALING_EXCEPTION_1(code,NULL)

/*inline   std::ostream&
operator<<( std::ostream& __os, const flexisip::SignalingException& e) {
	__os << dynamic_cast<const FlexisipException&>(e);
	return __os;
}*/

#endif /* SIGNALINGEXCEPTION_HH_ */
