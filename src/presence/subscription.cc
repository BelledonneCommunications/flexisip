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

#include "subscription.hh"
#include "belle-sip/belle-sip.h"
#include <time.h>
using namespace std;

namespace flexisip {

Subscription::Subscription(string eventName,unsigned int expires,belle_sip_dialog_t* aDialog, belle_sip_provider_t* prov)
	:mEventName(eventName)
	,mExpires(expires)
	,mDialog(aDialog)
	,mState(active)
	,mProv(prov){
	
		belle_sip_object_ref(mDialog);
		belle_sip_object_ref(mProv);
		time(&creationTime);
}
void Subscription::setAcceptHeader(belle_sip_header_t* acceptHeader) {
	if (mAcceptHeader) belle_sip_object_unref(mAcceptHeader);
	if (acceptHeader) {
		belle_sip_object_ref(acceptHeader); 
		mAcceptHeader = acceptHeader;
	}
}
	void Subscription::Subscription::setId(string& id){
		mId=id;
	}
	const char* Subscription::stateToString(State aState) {
		switch (aState) {
			case active: return BELLE_SIP_SUBSCRIPTION_STATE_ACTIVE;
			case pending: return BELLE_SIP_SUBSCRIPTION_STATE_PENDING;
			case terminated: return BELLE_SIP_SUBSCRIPTION_STATE_TERMINATED;
	
		}
	}
	void Subscription::notify(belle_sip_header_content_type_t * content_type, string& body) {
		if (belle_sip_dialog_get_state(mDialog) != BELLE_SIP_DIALOG_CONFIRMED) {
			SLOGE << "Cannot notify information change for ["<<std::hex <<(long)this<<"] because dialog ["<<std::hex <<(long)mDialog <<"]is in state ["<< belle_sip_dialog_state_to_string(belle_sip_dialog_get_state(mDialog)) <<"]" ;
			return;
		}
		belle_sip_request_t* notify=belle_sip_dialog_create_queued_request(mDialog,"NOTIFY");
		belle_sip_message_add_header((belle_sip_message_t*)notify,belle_sip_header_create("Event",mEventName.c_str()));
		
		if (content_type) {
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(content_type));
			belle_sip_message_set_body(BELLE_SIP_MESSAGE(notify), body.c_str(), (int)body.length());
		}
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(belle_sip_header_content_length_create((int)body.length())));
		
		
		/*RFC 3265
		 *
		 *3.2.2. Notifier NOTIFY Behavior
		 *NOTIFY requests MUST contain a "Subscription-State" header with a
		 *value of "active", "pending", or "terminated".  The "active" value
		 *indicates that the subscription has been accepted and has been
		 *authorized (in most cases; see section 5.2.).  The "pending" value
		 *indicates that the subscription has been received, but that policy
		 *information is insufficient to accept or deny the subscription at
		 *this time.  The "terminated" value indicates that the subscription is
		 *not active.
		 */
		time_t current_time;
		time(&current_time);
		
		belle_sip_header_subscription_state_t* sub_state = belle_sip_header_subscription_state_new();
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify),BELLE_SIP_HEADER(sub_state));
		
		belle_sip_header_subscription_state_set_state(sub_state, stateToString(mState));

		if (mState==active) {
			belle_sip_header_subscription_state_set_expires(sub_state, (int)(mExpires + creationTime - current_time));
		}
		
		belle_sip_client_transaction_t* client_transaction = belle_sip_provider_create_client_transaction(mProv,notify);
		if (belle_sip_client_transaction_send_request(client_transaction)) {
			SLOGE << "Cannot send notify information change for ["<<std::hex <<(long)this<<"]";
		}
		
	}
	Subscription::~Subscription() {
		belle_sip_object_unref(mDialog);
		belle_sip_object_unref(mProv);
	}

	
	
	Subscription::State Subscription::getState() const {
		return mState;
	}
	void Subscription::setState(Subscription::State state) {
		mState=state;
	}
	void Subscription::setExpire(int expires) {
		mExpires = expires;
	}
	
	//Presence Subscription
	
	
	PresenceSubscription::PresenceSubscription(unsigned int expires,const belle_sip_uri_t* presentity, belle_sip_dialog_t* aDialog,belle_sip_provider_t* aProv)
	:Subscription("Presence",expires,aDialog,aProv),mPresentity((belle_sip_uri_t*)belle_sip_object_clone(BELLE_SIP_OBJECT(presentity))){
		belle_sip_object_ref((void*)mPresentity);
	}
	PresenceSubscription::~PresenceSubscription() {
		belle_sip_object_unref((void*)mPresentity);
		
	}
	const belle_sip_uri_t* PresenceSubscription::getPresentityUri() {
		return mPresentity;
	}
	void PresenceSubscription::onInformationChanged(PresentityPresenceInformation& presenceInformation) {
		string body;
		belle_sip_header_content_type_t* content_type=NULL;
		if (getState() == active) {
			body+=presenceInformation.getPidf();
			content_type=belle_sip_header_content_type_create("application","pidf+xml");
		}
		
 		notify(content_type,body);
	}
	
	void PresenceSubscription::onExpired(PresentityPresenceInformation& presenceInformation) {
		//just transition state to expired
		setState(Subscription::State::terminated);
	}
	
	
}
