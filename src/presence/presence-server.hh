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
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include "belle-sip/sip-uri.h"

#include "bellesip-signaling-exception.hh"
#include "etag-manager.hh"
#include "presentity-manager.hh"
#include "service-server.hh"
#include "utils/threadpool.hh"

typedef struct belle_sip_main_loop belle_sip_main_loop_t;
typedef struct belle_sip_stack belle_sip_stack_t;
typedef struct belle_sip_provider belle_sip_provider_t;
typedef struct belle_sip_dialog_terminated_event belle_sip_dialog_terminated_event_t;
typedef struct belle_sip_io_error_event belle_sip_io_error_event_t;
typedef struct belle_sip_request_event belle_sip_request_event_t;
typedef struct belle_sip_response_event belle_sip_response_event_t;
typedef struct belle_sip_timeout_event belle_sip_timeout_event_t;
typedef struct belle_sip_transaction_terminated_event belle_sip_transaction_terminated_event_t;
typedef struct structbelle_sip_listener_t belle_sip_listener_t;



namespace pidf {
class tuple;
}
namespace flexisip {

class Subscription;
class PresentityPresenceInformation;
class Listener;

//Purpose of this class is to be notify when a presence info is created or when a new listener is added for a presence info. Used by long term presence
class PresenceInfoObserver {
public:
	PresenceInfoObserver(){};
	virtual ~PresenceInfoObserver(){};
	//notified when a listener is added or refreshed
	virtual void onListenerEvent(const std::shared_ptr<PresentityPresenceInformation>& info) const = 0;
	//notified when a listener is added or refreshed
	virtual void onListenerEvents(std::list<std::shared_ptr<PresentityPresenceInformation>>& infos) const = 0;
};

class PresenceServer : public PresentityManager, public ServiceServer {
public:
	PresenceServer();
	PresenceServer(bool withThread, su_root_t* root = nullptr);
	~PresenceServer();
	void _init() override;
	void _run() override;
	void _stop() override;
	belle_sip_main_loop_t* getBelleSipMainLoop();
	void addPresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver> &observer);
	void removePresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver> &observer);
private:
	// Used to declare the service configuration
	class Init {
	public:
		Init();
	};
	static Init sStaticInit;
	//PresenceConfigManager mConfigManager;
	belle_sip_stack_t *mStack;
	belle_sip_provider_t *mProvider;
	belle_sip_listener_t *mListener;
	int mDefaultExpires;
	std::string mBypass;
	std::string mRequest;
#if ENABLE_SOCI
	soci::connection_pool *mConnPool;
#endif
	ThreadPool *mThreadPool;
	bool mEnabled;
	size_t mMaxPresenceInfoNotifiedAtATime;

	// belle sip cbs
	static void processDialogTerminated(PresenceServer * thiz, const belle_sip_dialog_terminated_event_t *event);
	static void processIoError(PresenceServer * thiz, const belle_sip_io_error_event_t *event);
	static void processRequestEvent(PresenceServer * thiz, const belle_sip_request_event_t *event);
	static void processResponseEvent(PresenceServer * thiz, const belle_sip_response_event_t *event);
	static void processTimeout(PresenceServer * thiz, const belle_sip_timeout_event_t *event) ;
	static void processTransactionTerminated(PresenceServer * thiz, const belle_sip_transaction_terminated_event_t *event);
	void _start(bool withThread);
	void processPublishRequestEvent(const belle_sip_request_event_t *event);
	void processSubscribeRequestEvent(const belle_sip_request_event_t *event);


	/*
	 *Publish API
	 *
	 */
	const std::shared_ptr<PresentityPresenceInformation> getPresenceInfo(const std::string& eTag) const ;
	/*
	 * @throw in case an entry already exist for this entity;
	 * */
	std::shared_ptr<PresentityPresenceInformation> getPresenceInfo(const belle_sip_uri_t* identity) const ;
	void addPresenceInfo(const std::shared_ptr<PresentityPresenceInformation>& );

	void invalidateETag(const std::string& eTag) override;
	void modifyEtag(const std::string& oldEtag, const std::string& newEtag) override;
	void addEtag(const std::shared_ptr<PresentityPresenceInformation>& info,const std::string& etag) override;
	std::map<std::string,std::shared_ptr<PresentityPresenceInformation>> mPresenceInformationsByEtag;
	std::unordered_map<const belle_sip_uri_t*,std::shared_ptr<PresentityPresenceInformation>,std::hash<const belle_sip_uri_t*>,bellesip::UriComparator> mPresenceInformations;

	/*
	 *Presentity API
	 *
	 */

	void addOrUpdateListener(std::shared_ptr<PresentityPresenceInformationListener>& listerner,int expires) override;
	void addOrUpdateListener(std::shared_ptr<PresentityPresenceInformationListener>& listerner) override;
	void addOrUpdateListeners(std::list<std::shared_ptr<PresentityPresenceInformationListener>>& listerner,int expires);
	void addOrUpdateListeners(std::list<std::shared_ptr<PresentityPresenceInformationListener>>& listerner);
	void removeListener(const std::shared_ptr<PresentityPresenceInformationListener>& listerner) override;

	void removeSubscription(std::shared_ptr<Subscription> &identity);
	//void notify(Subscription& subscription,PresentityPresenceInformation& presenceInformation);
	std::unordered_map<const belle_sip_uri_t*,std::list<std::shared_ptr<Subscription>>,std::hash<const belle_sip_uri_t*>,bellesip::UriComparator> mSubscriptionsByEntity;
	/**/
	std::vector<std::shared_ptr<PresenceInfoObserver> > mPresenceInfoObservers;
};

}
#endif /* defined(__flexisip__presence_server__) */
