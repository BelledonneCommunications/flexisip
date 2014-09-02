//
//  subscription.hh
//  flexisip
//
//  Created by jeh on 18/06/14.
//  Copyright (c) 2014 Belledonne Communications. All rights reserved.
//

#ifndef flexisip_subscription_hh
#define flexisip_subscription_hh
#include <string>
#include "belle-sip/belle-sip.h"

using namespace std;

namespace flexisip {
	class Subscription {
	public:
		Subscription(string eventName,unsigned int expires);
		void setAcceptHeader(belle_sip_header_t* acceptHeader);
		void setId(string& id);
		void notify(belle_sip_header_content_type_t * content_type, string& body);
	private:
		string mEventName;
		string mEventId;
		belle_sip_header_t* mAcceptHeader;
		string state;
		unsigned int expires;
	
	
	
	};
	
	
	
	
	class PresenceSubscription : public Subscription {
	public:
		PresenceSubscription(unsigned int expires,const belle_sip_uri_t* presentity);
	private:
		const belle_sip_uri_t* mPresentity;

	};
}


#endif
