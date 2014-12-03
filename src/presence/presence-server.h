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

#ifndef __flexisip__presence_server__
#define __flexisip__presence_server__

#include <iostream>
#include <thread>
#include <map>
#include "signaling-exception.hh"
#include "etag-manager.hh"
//#include "presence-configmanager.hh"
#include "presentity-presenceinformation.hh"
#include "presentity-manager.hh"

typedef struct belle_sip_stack belle_sip_stack_t;
typedef struct belle_sip_provider belle_sip_provider_t;
typedef struct belle_sip_dialog_terminated_event belle_sip_dialog_terminated_event_t;
typedef struct belle_sip_io_error_event belle_sip_io_error_event_t;
typedef struct belle_sip_request_event belle_sip_request_event_t;
typedef struct belle_sip_response_event belle_sip_response_event_t;
typedef struct belle_sip_timeout_event belle_sip_timeout_event_t;
typedef struct belle_sip_transaction_terminated_event belle_sip_transaction_terminated_event_t;
typedef struct structbelle_sip_listener_t belle_sip_listener_t;

namespace flexisip {
struct BelleSipUriComparator : public std::binary_function<belle_sip_uri_t*, belle_sip_uri_t*, bool> {
	bool operator()(const belle_sip_uri_t* lhs, const belle_sip_uri_t* rhs) const;
};

namespace pidf {
class tuple;
}
	class Subscription;
	
class PresenceServer :  EtagManager,PresentityManager {
public:
	PresenceServer(std::string configFile) throw (FlexisipException);
	~PresenceServer();
	void start() throw (FlexisipException);
private:

	//PresenceConfigManager mConfigManager;
	belle_sip_stack_t *mStack;
	belle_sip_provider_t *mProvider;
	belle_sip_listener_t *mListener;
	thread mIterateThread;
	int mDefaultExpires;
	// belle sip cbs
	static void processDialogTerminated(PresenceServer * thiz, const belle_sip_dialog_terminated_event_t *event);
	static void processIoError(PresenceServer * thiz, const belle_sip_io_error_event_t *event);
	static void processRequestEvent(PresenceServer * thiz, const belle_sip_request_event_t *event);
	static void processResponseEvent(PresenceServer * thiz, const belle_sip_response_event_t *event);
	static void processTimeout(PresenceServer * thiz, const belle_sip_timeout_event_t *event) ;
	static void processTransactionTerminated(PresenceServer * thiz, const belle_sip_transaction_terminated_event_t *event);

	void processPublishRequestEvent(const belle_sip_request_event_t *event) throw (SignalingException,FlexisipException);
	void processSubscribeRequestEvent(const belle_sip_request_event_t *event) throw (SignalingException,FlexisipException);

	
	/*
	 *Publish API
	 *
	 */
	PresentityPresenceInformation* getPresenceInfo(const string& eTag) const ;
	/*
	 * @throw in case an entry already exist for this entity;
	 * */
	PresentityPresenceInformation* getPresenceInfo(const belle_sip_uri_t* identity) const ;
	void addPresenceInfo(PresentityPresenceInformation*) throw (FlexisipException);
	void invalidateEtag(string eTag);
	void invalidateETag(const string& eTag) ;
	void modifyEtag(const string& oldEtag, const string& newEtag) throw (FlexisipException);
	void addEtag(PresentityPresenceInformation* info,const string& etag) throw (FlexisipException);
	map<std::string,shared_ptr<PresentityPresenceInformation*>> mPresenceInformationsByEtag;
	map<const belle_sip_uri_t*,shared_ptr<PresentityPresenceInformation*>,BelleSipUriComparator> mPresenceInformations;

	/*
	 *Presentity API
	 *
	 */
	
	 void addOrUpdateListener(PresentityPresenceInformation::Listener& listerner,int expires);
	 void removeListener(PresentityPresenceInformation::Listener& listerner);
	
	//Subscription* getSubscription(const belle_sip_uri_t* identity) const ;
	//void notify(Subscription& subscription,PresentityPresenceInformation& presenceInformation) throw (FlexisipException);
	map<const belle_sip_uri_t*,list<shared_ptr<Subscription>>,BelleSipUriComparator> mSubscriptionsByEntity;


};
}
#endif /* defined(__flexisip__presence_server__) */
