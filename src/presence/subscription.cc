/*
	:, a flexible SIP proxy server with media capabilities.
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

#include <time.h>

#include "belle-sip/belle-sip.h"

#include <flexisip/logmanager.hh>
#include "subscription.hh"

using namespace std;

namespace flexisip {

Subscription::Subscription(const string &eventName, unsigned int expires, const bellesip::weak_ptr<belle_sip_dialog_t> &aDialog,
						   belle_sip_provider_t *prov)
	: mDialog{aDialog}, mProv{prov}, mEventName{eventName} {
	time(&mCreationTime);
	mExpirationTime = mCreationTime + expires;
}
void Subscription::setAcceptHeader(belle_sip_header_t *acceptHeader) {
	if (acceptHeader) belle_sip_object_ref(acceptHeader);
	mAcceptHeader.reset(acceptHeader);
}
void Subscription::setAcceptEncodingHeader(belle_sip_header_t *acceptEncodingHeader) {
	if (acceptEncodingHeader) belle_sip_object_ref(acceptEncodingHeader);
	mAcceptEncodingHeader.reset(acceptEncodingHeader);
}

const char *Subscription::stateToString(State aState) {
	switch (aState) {
		case active:
			return BELLE_SIP_SUBSCRIPTION_STATE_ACTIVE;
		case pending:
			return BELLE_SIP_SUBSCRIPTION_STATE_PENDING;
		case terminated:
			return BELLE_SIP_SUBSCRIPTION_STATE_TERMINATED;
	}
	return "Unknown state";
}

void Subscription::notify(belle_sip_header_content_type_t *content_type, const string *body,
						  belle_sip_multipart_body_handler_t *multiPartBody, const string *content_encoding) {
	auto dialog = mDialog.lock();
	if (!dialog) {
		SLOGI << "Cannot notify information change for [" << this << "] because dialog no more exists";
		return;
	}
	if (belle_sip_dialog_get_state(dialog.get()) != BELLE_SIP_DIALOG_CONFIRMED) {
		SLOGI << "Cannot notify information change for [" << this << "] because dialog [" << dialog.get() << "] is in state ["
			  << belle_sip_dialog_state_to_string(belle_sip_dialog_get_state(dialog.get())) << "]";
		return;
	}
	belle_sip_request_t *notify = belle_sip_dialog_create_queued_request(dialog.get(), "NOTIFY");
	belle_sip_message_add_header((belle_sip_message_t *)notify, belle_sip_header_create("Event", mEventName.c_str()));

	if (content_type && body) {
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(content_type));
		belle_sip_message_set_body(BELLE_SIP_MESSAGE(notify), body->c_str(), (int)body->length());
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(belle_sip_header_content_length_create((int)body->length())));
	} else if (multiPartBody) {
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), belle_sip_header_create("Require", "eventlist"));
		belle_sip_multipart_body_handler_set_related(multiPartBody, TRUE);
		belle_sip_message_set_body_handler(BELLE_SIP_MESSAGE(notify), BELLE_SIP_BODY_HANDLER(multiPartBody));
		if (content_encoding && mAcceptEncodingHeader) {
			const char *accept_encoding = belle_sip_header_get_unparsed_value(mAcceptEncodingHeader.get());
			if (accept_encoding && (strcmp(accept_encoding, content_encoding->c_str()) == 0)) {
				belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), belle_sip_header_create("Content-Encoding", content_encoding->c_str()));
			}
		}
	}

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

	belle_sip_header_subscription_state_t *sub_state = belle_sip_header_subscription_state_new();
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(sub_state));

	// fixme use git version
	belle_sip_header_user_agent_t *userAgent = belle_sip_header_user_agent_new();
	belle_sip_header_user_agent_add_product(userAgent, "flexisip-presence");
	belle_sip_message_add_header(BELLE_SIP_MESSAGE(notify), BELLE_SIP_HEADER(userAgent));

	belle_sip_header_subscription_state_set_state(sub_state, stateToString(mState));

	if (mState == active) {
		belle_sip_header_subscription_state_set_expires(sub_state, (int)(mExpirationTime - current_time));
	}

	mCurrentTransaction = belle_sip_provider_create_client_transaction(mProv, notify);
	setSubscription(mCurrentTransaction, shared_from_this());
	if (belle_sip_client_transaction_send_request(mCurrentTransaction)) {
		SLOGE << "Cannot send notify information change for [" << this << "]";
	}
}

const belle_sip_uri_t* Subscription::getFrom() {
	return belle_sip_header_address_get_uri(belle_sip_dialog_get_local_party(mDialog.lock().get()));
}
const belle_sip_uri_t* Subscription::getTo() {
	return belle_sip_header_address_get_uri(belle_sip_dialog_get_remote_party(mDialog.lock().get()));
}
// Presence Subscription

PresenceSubscription::PresenceSubscription(unsigned int expires, const belle_sip_uri_t *presentity,
										   const bellesip::weak_ptr<belle_sip_dialog_t> &aDialog, belle_sip_provider_t *aProv)
	: Subscription{"Presence", expires, aDialog, aProv},
	  mPresentity{(belle_sip_uri_t *)belle_sip_object_ref(belle_sip_object_clone(BELLE_SIP_OBJECT(presentity)))} {}

PresenceSubscription::~PresenceSubscription() {
	SLOGD << "PresenceSubscription [" << this << "] deleted";
}

void PresenceSubscription::onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extended) {
	string body;
	belle_sip_header_content_type_t *content_type = NULL;
	try {
		if (getState() == active) {
			body += presenceInformation.getPidf(extended);
			content_type = belle_sip_header_content_type_create("application", "pidf+xml");
		}
	} catch (FlexisipException &e) {
		SLOGD << "Cannot notify [" << this->getPresentityUri() << "] caused by [" << e << "]";
		return;
	}

	notify(content_type, body);
}

void PresenceSubscription::onExpired([[maybe_unused]] PresentityPresenceInformation &presenceInformation) {
	// just transition state to expired
	setState(Subscription::State::terminated);
}

}
