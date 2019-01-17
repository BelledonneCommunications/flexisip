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

#pragma once

#include <string>

#include "belle-sip/belle-sip.h"

#include "presentity-presenceinformation.hh"

namespace flexisip {
	class Subscription : public std::enable_shared_from_this<Subscription>{

  public:
	enum State { active, pending, terminated };
	Subscription(const std::string &eventName, unsigned int expires, belle_sip_dialog_t *aDialog, belle_sip_provider_t *prov);
	virtual ~Subscription();
	void setAcceptHeader(belle_sip_header_t *acceptHeader);
	void setAcceptEncodingHeader(belle_sip_header_t *acceptEncodingHeader);
	void setId(const std::string &id);
	void notify(belle_sip_header_content_type_t *content_type, const std::string &body);
	void notify(belle_sip_multipart_body_handler_t *body);
	void notify(belle_sip_multipart_body_handler_t *body, const std::string &content_encoding);
	static const char *stateToString(State aState);
	State getState() const;
	void setState(Subscription::State state);
	/*
	 * used to set expiration value
	 */
	void setExpirationTime(time_t expirationTime);
	time_t getExpirationDate();
	void increaseExpirationTime(unsigned int expires);
	const belle_sip_uri_t* getFrom();
	const belle_sip_uri_t* getTo();

	std::shared_ptr<Subscription> mDialogRef; // Keep ref of c++ shared_ptr in belle_sip_dialog
	std::shared_ptr<Subscription> mTransactionRef; // Keep ref of c++ shared_ptr in belle_sip_transaction
	belle_sip_client_transaction_t *mCurrentTransaction = NULL;

  protected:
	belle_sip_dialog_t *mDialog;
	belle_sip_provider_t *mProv;

  private:
	Subscription(const Subscription &);
	void notify(belle_sip_header_content_type_t *content_type, const std::string *body,
				belle_sip_multipart_body_handler_t *multiPartBody, const std::string *content_encoding);
	std::string mEventName;
	belle_sip_header_t *mAcceptHeader;
	belle_sip_header_t *mAcceptEncodingHeader;
	std::string mId;
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
	void onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extented);
	void onExpired(PresentityPresenceInformation &presenceInformation);
	const belle_sip_uri_t* getFrom();
	const belle_sip_uri_t* getTo();
  private:
	const belle_sip_uri_t *mPresentity;
};
}