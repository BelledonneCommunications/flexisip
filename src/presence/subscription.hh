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

#ifndef flexisip_subscription_hh
#define flexisip_subscription_hh
#include <string>
#include "belle-sip/belle-sip.h"
#include "presentity-presenceinformation.hh"
using namespace std;

namespace flexisip {
	class Subscription {

	public:
		enum State {
			active, pending, terminated
		};
		Subscription(string eventName,unsigned int expires,belle_sip_dialog_t* aDialog,belle_sip_provider_t* prov);
		~Subscription();
		void setAcceptHeader(belle_sip_header_t* acceptHeader);
		void setId(string& id);
		void notify(belle_sip_header_content_type_t * content_type, string& body);
		static const char* stateToString(State aState);
		State getState() const;
		void setState(Subscription::State state);
		/*
		 * used to update expire value
		 */
		void setExpire(int expires);
	private:
		string mEventName;
		string mEventId;
		belle_sip_header_t* mAcceptHeader;
		string state;
		unsigned int mExpires;
		string mId;
		belle_sip_dialog_t* mDialog;
		State mState;
		time_t creationTime;
		belle_sip_provider_t* mProv;
	
	};
	
	
	
	/**
	 ** Presence subscription object host a subscription to a opresence entity. This object has the same live cycle has a subscription dialog
	 */
	class PresenceSubscription : public Subscription, public PresentityPresenceInformationListener {
	public:
		PresenceSubscription(unsigned int expires,const belle_sip_uri_t* presentity,belle_sip_dialog_t* aDialog,belle_sip_provider_t* aProv);
		~PresenceSubscription();
	
		
		
		const belle_sip_uri_t* getPresentityUri(void);
		/*
		 * This function is call every time Presentity information need to be notified to a UA
		 */
		void onInformationChanged(PresentityPresenceInformation& presenceInformation);
		void onExpired(PresentityPresenceInformation& presenceInformation);
		
	private:
		const belle_sip_uri_t* mPresentity;
		

	};
}


#endif
