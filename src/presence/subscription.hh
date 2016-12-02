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
	class Subscription : public enable_shared_from_this<Subscription>{

  public:
	enum State { active, pending, terminated };
	Subscription(const string &eventName, unsigned int expires, belle_sip_dialog_t *aDialog, belle_sip_provider_t *prov);
	virtual ~Subscription();
	void setAcceptHeader(belle_sip_header_t *acceptHeader);
	void setAcceptEncodingHeader(belle_sip_header_t *acceptEncodingHeader);
	void setId(const string &id);
	void notify(belle_sip_header_content_type_t *content_type, const string &body);
	void notify(belle_sip_multipart_body_handler_t *body);
	void notify(belle_sip_multipart_body_handler_t *body, const string &content_encoding);
	static const char *stateToString(State aState);
	State getState() const;
	void setState(Subscription::State state);
	/*
	 * used to set expiration value
	 */
	void setExpirationTime(time_t expirationTime);
	time_t getExpirationDate();
	void increaseExpirationTime(unsigned int expires);

  protected:
	belle_sip_dialog_t *mDialog;
	belle_sip_provider_t *mProv;

  private:
	Subscription(const Subscription &);
	void notify(belle_sip_header_content_type_t *content_type, const string *body,
				belle_sip_multipart_body_handler_t *multiPartBody, const string *content_encoding);
	string mEventName;
	belle_sip_header_t *mAcceptHeader;
	belle_sip_header_t *mAcceptEncodingHeader;
	string mId;
	State mState;
	time_t mCreationTime;
	time_t mExpirationTime;
};

/**
 ** Presence subscription object host a subscription to a opresence entity. This object has the same live cycle has a
 *subscription dialog
 */
class PresenceSubscription : public Subscription, public PresentityPresenceInformationListener {
  public:
	PresenceSubscription(unsigned int expires, const belle_sip_uri_t *presentity, belle_sip_dialog_t *aDialog,
						 belle_sip_provider_t *aProv);
	virtual ~PresenceSubscription();

	const belle_sip_uri_t *getPresentityUri(void) const;
	/*
	 * This function is call every time Presentity information need to be notified to a UA
	 */
	void onInformationChanged(PresentityPresenceInformation &presenceInformation);
	void onExpired(PresentityPresenceInformation &presenceInformation);

  private:
	const belle_sip_uri_t *mPresentity;
};
}

#endif
