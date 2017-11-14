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

#ifndef flexisip_rls_subscription_hh
#define flexisip_rls_subscription_hh
#include "subscription.hh"
#include "rlmi+xml.hh"
#include <unordered_map>
#include <chrono>
typedef struct _belle_sip_uri belle_sip_uri_t;
typedef struct belle_sip_server_transaction belle_sip_server_transaction_t;
namespace flexisip {
class ListSubscription;

/*
 * this class instanciate a resource as defined by rfc4662 (I.E a presentity from a resource-list)
 */
class PresentityResourceListener : public PresentityPresenceInformationListener {
  public:
	PresentityResourceListener(ListSubscription &aListSubscription, const belle_sip_uri_t *presentity);
	PresentityResourceListener(const PresentityResourceListener &);
	~PresentityResourceListener();

	const belle_sip_uri_t *getPresentityUri(void) const;
	/*
	 * This function is call every time Presentity information need to be notified to a UA
	 */
	void onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extended);
	void onExpired(PresentityPresenceInformation &presenceInformation);
	const belle_sip_uri_t* getFrom();
	const belle_sip_uri_t* getTo();

  private:
	ListSubscription &mListSubscription;
	belle_sip_uri_t *mPresentity;
};

/*
 * This class manage a subscription for a list of presentities.
 */
class ListSubscription : public Subscription {
  public:
	// ListSubscription(unsigned int expires,list<const belle_sip_uri_t *> resources,belle_sip_dialog_t*
	// aDialog,belle_sip_provider_t* aProv);
	ListSubscription(unsigned int expires, belle_sip_server_transaction_t *ist,
					 belle_sip_provider_t *aProv) throw(FlexisipException);

	virtual ~ListSubscription();
	std::list<std::shared_ptr<PresentityPresenceInformationListener>> &getListeners();
	/* Notify taking state from all pending Presentity listener*/
	void notify(bool isFullState) throw(FlexisipException);

  protected:
	// this function is call by each PresentityResourceListener to centralize notifications
	friend PresentityResourceListener;
	void onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extended);

  private:
	ListSubscription(const ListSubscription &);
	// return true if a real notify can be sent.
	bool isTimeToNotify();
	void addInstanceToResource(Xsd::Rlmi::Resource &resource, std::list<belle_sip_body_handler_t *> &multipartList,
							   PresentityPresenceInformation &presentityInformation, bool extended);

	std::list<std::shared_ptr<PresentityPresenceInformationListener>> mListeners;
	typedef std::unordered_map<const belle_sip_uri_t *, std::pair<std::shared_ptr<PresentityPresenceInformation>,bool>,
						  std::hash<const belle_sip_uri_t *>, bellesip::UriComparator> PendingStateType;
	PendingStateType mPendingStates; // map of Presentity to be notified by uri
	std::chrono::time_point<std::chrono::system_clock> mLastNotify;
	std::chrono::seconds mMinNotifyInterval;
	/*
	 * rfc 4662
	 * 5.2.  List Attributes
	 * ....
	 * The first mandatory <list> attribute is "uri", which contains the uri
	 * that corresponds to the list.  Typically, this is the URI to which
	 * the SUBSCRIBE request was sent.
	 **/
	const belle_sip_uri_t *mName;
	/*
	 * rfc 4662
	 * 5.2.  List Attributes
	 * ....
	 * The second mandatory <list> attribute is "version", which contains a
	 * number from 0 to 2^32-1.  This version number MUST be 0 for the first
	 * NOTIFY message sent within a subscription, and MUST increase by
	 * exactly one for each subsequent NOTIFY sent within a subscription.
	 */
	uint32_t mVersion;

	belle_sip_source_t *mTimer;
};
}

#endif
