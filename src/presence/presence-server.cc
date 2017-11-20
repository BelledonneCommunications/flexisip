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

#include "presence-server.hh"
#include "belle-sip/belle-sip.h"
#include "pidf+xml.hxx"
#include "resource-lists.hxx"
#include "presentity-presenceinformation.hh"
#include "list-subscription.hh"
#include "bellesip-signaling-exception.hh"
#include "subscription.hh"
#include "configmanager.hh"
#include <string.h>
#include <signal.h>
#include <algorithm>

using namespace pidf;
using namespace flexisip;
using namespace std;

void _belle_sip_log(const char *domain, BctbxLogLevel lev, const char *fmt, va_list args){
	LOGV(lev, fmt, args);
}

PresenceServer::Init PresenceServer::sStaticInit;

PresenceServer::Init::Init() {
	ConfigItemDescriptor items[] = {
									{Boolean, "enabled", "Enable presence server", "true"},
									{StringList, "transports",
									 "List of white space separated SIP uris where the presence server must listen. Must not be tls.",
									 "sip:127.0.0.1:5065;transport=tcp"},
									 {Integer, "expires", "Publish default expires in second.  by default.", "600"},
									{Boolean, "leak-detector", "Enable belle-sip leak detector", "false"},
									{Boolean, "long-term-enabled", "Enable long-term presence notifies", "true"},
									{String, "bypass-condition", "If user agent contains it, can bypass extended notifiy verification.", "false"},
									config_item_end};
	GenericStruct *s = new GenericStruct("presence-server", "Flexisip presence server parameters.", 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}

PresenceServer::PresenceServer()
	: mStarted(true)
	, mIterateThread(nullptr) {
	
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("presence-server");
	/*Enabling leak detector should be done asap.*/
	belle_sip_object_enable_leak_detector(GenericManager::get()->getRoot()->get<GenericStruct>("presence-server")->get<ConfigBoolean>("leak-detector")->read());
	mStack = belle_sip_stack_new(NULL);
	mProvider = belle_sip_stack_create_provider(mStack, NULL);
	//bctbx_set_log_handler(_belle_sip_log);
	//belle_sip_set_log_level(BELLE_SIP_LOG_MESSAGE);

	xercesc::XMLPlatformUtils::Initialize();

	//	if (mConfigManager.load(configFile.c_str())==-1 ) {
	//		throw FLEXISIP_EXCEPTION <<"No configuration file found at [" << configFile << "] Please specify a valid
	//configuration file." ;
	//	}
	belle_sip_listener_callbacks_t listener_callbacks;

	memset(&listener_callbacks, 0, sizeof(listener_callbacks));
	listener_callbacks.process_dialog_terminated =
		(void (*)(void *, const belle_sip_dialog_terminated_event_t *))PresenceServer::processDialogTerminated;
	listener_callbacks.process_io_error =
		(void (*)(void *, const belle_sip_io_error_event_t *))PresenceServer::processIoError;
	listener_callbacks.process_request_event =
		(void (*)(void *, const belle_sip_request_event_t *))PresenceServer::processRequestEvent;
	listener_callbacks.process_response_event =
		(void (*)(void *, const belle_sip_response_event_t *))PresenceServer::processResponseEvent;
	listener_callbacks.process_timeout =
		(void (*)(void *, const belle_sip_timeout_event_t *))PresenceServer::processTimeout;
	listener_callbacks.process_transaction_terminated =
		(void (*)(void *,
				  const belle_sip_transaction_terminated_event_t *))PresenceServer::processTransactionTerminated;
	mListener = belle_sip_listener_create_from_callbacks(&listener_callbacks, this);
	belle_sip_provider_add_sip_listener(mProvider, mListener);
	mDefaultExpires = config->get<ConfigInt>("expires")->read();
	mBypass = config->get<ConfigString>("bypass-condition")->read();
	mEnabled = config->get<ConfigBoolean>("enabled")->read();
}

static void remove_listening_point(belle_sip_listening_point_t* lp,belle_sip_provider_t* prov) {
	belle_sip_provider_remove_listening_point(prov,lp);
}

PresenceServer::~PresenceServer() {
	belle_sip_provider_clean_channels(mProvider);
	const belle_sip_list_t * lps = belle_sip_provider_get_listening_points(mProvider);
	belle_sip_list_t * tmp_list = belle_sip_list_copy(lps);
	belle_sip_list_for_each2 (tmp_list,(void (*)(void*,void*))remove_listening_point,mProvider);
	belle_sip_list_free(tmp_list);

	stop();
	belle_sip_object_unref(mProvider);
	belle_sip_object_unref(mStack);
	belle_sip_object_unref(mListener);
	// must be done before cleaning xerces
	if (mPresenceInformations.size()) SLOGD << "Still ["<<mPresenceInformations.size()<<"] PresenceInformations referenced, clearing";
	mPresenceInformations.clear();
	if (mPresenceInformationsByEtag.size()) SLOGD << "Still ["<<mPresenceInformationsByEtag.size()<<"] PresenceInformationsByEtag referenced, clearing";
	mPresenceInformationsByEtag.clear();
	xercesc::XMLPlatformUtils::Terminate();
	belle_sip_object_dump_active_objects();
	belle_sip_object_flush_active_objects();
	SLOGD << "Presence server destroyed";
}

void PresenceServer::_start(bool withThread) {
	if (!mEnabled) return;
	GenericStruct *cr = GenericManager::get()->getRoot();
	std::string get_users_with_phones_request = cr->get<GenericStruct>("module::Authentication")
												  ->get<ConfigString>("soci-users-with-phones-request")
												  ->read();
	if(get_users_with_phones_request == "") {
		LOGF("Unable to start presence server : soci-users-with-phones-request is not precised in flexisip.conf, please fix it.");
	}

	list<string> transports = cr->get<GenericStruct>("presence-server")
								->get<ConfigStringList>("transports")
								->read();

	for (auto it = transports.begin(); it != transports.end(); ++it) {
		string transport = *it;
		if(transport.find("sips") != string::npos || transport.find("transport=tls") != string::npos) {
			LOGF("Unable to start presence server : TLS transport is not supported by the presence server.");
		}
		belle_sip_uri_t *uri = belle_sip_uri_parse(it->c_str());
		if (uri) {
			belle_sip_listening_point_t *lp = belle_sip_stack_create_listening_point(
				mStack, belle_sip_uri_get_host(uri), belle_sip_uri_get_listening_port(uri),
				belle_sip_uri_get_transport_param(uri) ? belle_sip_uri_get_transport_param(uri) : "udp");
			belle_sip_object_unref(uri);
			if (belle_sip_provider_add_listening_point(mProvider, lp))
				throw FLEXISIP_EXCEPTION << "Cannot add lp for [" << *it << "]";
		}
	}
	if (withThread){
		mIterateThread.reset (new thread([this]() {
			while (mStarted)
				belle_sip_main_loop_run(belle_sip_stack_get_main_loop(this->mStack)); // is not interrupted by add source
		}));
	}
}

void PresenceServer::start() {
	_start(true);
}

void PresenceServer::run() {
	_start(false);
	while (mStarted){
		belle_sip_main_loop_run(belle_sip_stack_get_main_loop(mStack));
	}
}

void PresenceServer::stop() {
	mStarted = false;
	belle_sip_main_loop_quit(belle_sip_stack_get_main_loop(mStack));
	if (mIterateThread) {
		pthread_kill(mIterateThread->native_handle(), SIGINT);//because main loop is not interruptible
		mIterateThread->join();
		mIterateThread.reset();
	}
}


void PresenceServer::processDialogTerminated(PresenceServer *thiz, const belle_sip_dialog_terminated_event_t *event) {
	belle_sip_dialog_t *dialog = belle_sip_dialog_terminated_event_get_dialog(event);
	if (belle_sip_dialog_get_application_data(dialog)) {
		shared_ptr<Subscription> &sub =
		*static_cast<shared_ptr<Subscription>*>(belle_sip_dialog_get_application_data(dialog));
		if (dynamic_pointer_cast<ListSubscription>(sub)) {
			SLOGD << "Subscription [" << sub.get() << "] has expired";
			sub->setState(Subscription::State::terminated);
			thiz->removeSubscription(sub);
		} //else  nothing to be done for now because expire is performed at SubscriptionLevel
		delete static_cast<shared_ptr<Subscription>*>(belle_sip_dialog_get_application_data(dialog));
	}
}
void PresenceServer::processIoError(PresenceServer *thiz, const belle_sip_io_error_event_t *event) {
	SLOGD << "PresenceServer::processIoError not implemented yet";
}
void PresenceServer::processRequestEvent(PresenceServer *thiz, const belle_sip_request_event_t *event) {
	belle_sip_request_t *request = belle_sip_request_event_get_request(event);
	try {
		if (strcmp(belle_sip_request_get_method(request), "PUBLISH") == 0) {
			thiz->processPublishRequestEvent(event);

		} else if (strcmp(belle_sip_request_get_method(request), "SUBSCRIBE") == 0) {
			thiz->processSubscribeRequestEvent(event);

		} else {
			throw BELLESIP_SIGNALING_EXCEPTION_1(405, BELLE_SIP_HEADER(belle_sip_header_allow_create("PUBLISH")))
				<< "Unsupported method [" << belle_sip_request_get_method(request) << "]";
		}
	} catch (BelleSipSignalingException &e) {
		SLOGE << e.what();
		belle_sip_response_t *resp = belle_sip_response_create_from_request(request, e.getStatusCode());
		for (belle_sip_header_t *header : e.getHeaders())
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp), header);
		belle_sip_provider_send_response(thiz->mProvider, resp);
		return;
	} catch (FlexisipException &e2) {
		SLOGE << e2;
		belle_sip_response_t *resp = belle_sip_response_create_from_request(request, 500);
		belle_sip_provider_send_response(thiz->mProvider, resp);
		return;
	} catch (std::exception &e3) {
		SLOGE << "Unknown exception [" << e3.what() <<" <<use FlexisipException instead";
		belle_sip_response_t *resp = belle_sip_response_create_from_request(request, 500);
		belle_sip_provider_send_response(thiz->mProvider, resp);
		return;
	}
}
void PresenceServer::processResponseEvent(PresenceServer *thiz, const belle_sip_response_event_t *event) {
	belle_sip_response_t* resp = belle_sip_response_event_get_response(event);
	int code = belle_sip_response_get_status_code(resp);
	if (code == 407) {
		SLOGE << __FUNCTION__ << ": presence server being challenged by flexisip probably means that flexisip is misconfigured. "
		"Presence server should be a trusted host.";
	} else {
		SLOGD << __FUNCTION__ << " not handled yet for " << code << ": " << belle_sip_response_get_reason_phrase(resp);
	}
}
void PresenceServer::processTimeout(PresenceServer *thiz, const belle_sip_timeout_event_t *event) {
	belle_sip_client_transaction_t *client = belle_sip_timeout_event_get_client_transaction(event);
	if (client && belle_sip_transaction_get_application_data(BELLE_SIP_TRANSACTION(client))) {
		shared_ptr<Subscription> &subscription =
			*static_cast<shared_ptr<Subscription>*>(belle_sip_transaction_get_application_data(BELLE_SIP_TRANSACTION(client)));
		thiz->removeSubscription(subscription);
		SLOGD << "Removing subscription [" << subscription.get()<< "] because no response received";
	}
}
void PresenceServer::processTransactionTerminated(PresenceServer *thiz,
												  const belle_sip_transaction_terminated_event_t *event) {
	belle_sip_client_transaction_t *client = belle_sip_transaction_terminated_event_get_client_transaction(event);
	if (client && belle_sip_transaction_get_application_data(BELLE_SIP_TRANSACTION(client))) {
		delete 	static_cast<shared_ptr<Subscription>*>(belle_sip_transaction_get_application_data(BELLE_SIP_TRANSACTION(client)));
	}
}

void PresenceServer::processPublishRequestEvent(const belle_sip_request_event_t *event) {
	belle_sip_request_t *request = belle_sip_request_event_get_request(event);
	std::shared_ptr<PresentityPresenceInformation> presenceInfo;

	/*rfc3903
	 *
	 * 6.  Processing PUBLISH Requests

	 The Event State Compositor (ESC) is a User Agent Server (UAS) that
	 processes and responds to PUBLISH requests, and maintains a list of
	 publications for a given address-of-record.  The ESC has to know
	 (e.g., through configuration) the set of addresses for which it
	 maintains event state.

	 The ESC MUST ignore the Record-Route header field if it is included
	 in a PUBLISH request.  The ESC MUST NOT include a Record-Route header
	 field in any response to a PUBLISH request.  The ESC MUST ignore the
	 Contact header field if one is present in a PUBLISH request.
	 PUBLISH requests with the same Request-URI MUST be processed in the
	 order that they are received.  PUBLISH requests MUST also be
	 processed atomically, meaning that a particular PUBLISH request is
	 either processed completely or not at all.

	 When receiving a PUBLISH request, the ESC follows the steps defining
	 general UAS behavior in Section 8.2 of RFC 3261 [4].  In addition,
	 for PUBLISH specific behavior the ESC follows these steps:

	 1. The ESC inspects the Request-URI to determine whether this request
	 is targeted to a resource for which the ESC is responsible for
	 maintaining event state.  If not, the ESC MUST return a 404 (Not
	 Found) response and skip the remaining steps.

	 It may also be that the Request-URI points to a domain that the
	 ESC is not responsible for.  In that case, the UAS receiving the
	 request can assume the role of a proxy server and forward the
	 request to a more appropriate target.

	 jehan: NOT implemented yet

	 2. The ESC examines the Event header field of the PUBLISH request.
	 If the Event header field is missing or contains an event package
	 which the ESC does not support, the ESC MUST respond to the
	 PUBLISH request with a 489 (Bad Event) response, and skip the
	 remaining steps.
	 */
	belle_sip_header_t *eventHeader = belle_sip_message_get_header(BELLE_SIP_MESSAGE(request), "Event");
	if (!eventHeader)
		throw BELLESIP_SIGNALING_EXCEPTION(489) << "No sip Event for request [" << std::hex << (long)request << "]";

	if (strcasecmp(belle_sip_header_get_unparsed_value(eventHeader), "Presence") != 0) {
		throw BELLESIP_SIGNALING_EXCEPTION(489) << "Unsuported  Event [" << belle_sip_header_get_unparsed_value(eventHeader)
									   << "for request [" << std::hex << (long)request << "]";
	}

	/*
	 3. The ESC examines the SIP-If-Match header field of the PUBLISH
	 request for the presence of a request precondition.
	 */
	belle_sip_header_t *sipIfMatch = belle_sip_message_get_header(BELLE_SIP_MESSAGE(request), "SIP-If-Match");
	belle_sip_header_content_type_t *contentType =
		belle_sip_message_get_header_by_type(request, belle_sip_header_content_type_t);
	string eTag;
	/*
	 *  If the request does not contain a SIP-If-Match header field,
	 the ESC MUST generate and store a locally unique entity-tag for
	 identifying the publication.  This entity-tag is associated
	 with the event-state carried in the body of the PUBLISH
	 request.
	 */
	if (!sipIfMatch) {
		if (!contentType || strcasecmp(belle_sip_header_content_type_get_type(contentType), "application") != 0 ||
			strcasecmp(belle_sip_header_content_type_get_subtype(contentType), "pidf+xml") != 0) {

			throw BELLESIP_SIGNALING_EXCEPTION_1(415, belle_sip_header_create("Accept", "application/pidf+xml"))
				<< "Unsupported media type ["
				<< (contentType ? belle_sip_header_content_type_get_type(contentType) : "not set") << "/"
				<< (contentType ? belle_sip_header_content_type_get_subtype(contentType) : "not set") << "]";
		}

	}
	/*
	 *  Else, if the request has a SIP-If-Match header field, the ESC
	 checks whether the header field contains a single entity-tag.
	 If not, the request is invalid, and the ESC MUST return with a
	 400 (Invalid Request) response and skip the remaining steps.

	 jehan: NOT checked

	 *  Else, the ESC extracts the entity-tag contained in the SIP-If-
	 Match header field and matches that entity-tag against all
	 locally stored entity-tags for this resource and event package.*/
	else {
		eTag = belle_sip_header_get_unparsed_value(sipIfMatch);

		/*      If no match is found, the ESC MUST reject the publication with
		 a response of 412 (Conditional Request Failed), and skip the
		 remaining steps.*/
		if (!(presenceInfo = getPresenceInfo(eTag)))
			throw BELLESIP_SIGNALING_EXCEPTION(412) << "Unknown eTag [" << eTag << " for request [" << std::hex << (long)request
										   << "]";
	}
	belle_sip_header_expires_t *headerExpires =
		belle_sip_message_get_header_by_type(request, belle_sip_header_expires_t);
	int expires;
	/*4. The ESC processes the Expires header field value from the PUBLISH
	 request.

	 *  If the request has an Expires header field, that value MUST be
	 taken as the requested expiration.
	 */
	if (headerExpires)
		expires = belle_sip_header_expires_get_expires(headerExpires);
	/*
	 *  Else, a locally-configured default value MUST be taken as the
	 requested expiration.
	 */ else
		expires = mDefaultExpires;
	/*
	 *  The ESC MAY choose an expiration less than the requested
	 expiration interval.  Only if the requested expiration interval
	 is greater than zero and less than a locally-configured
	 minimum, the ESC MAY reject the publication with a response of
	 423 (Interval Too Brief), and skip the remaining steps.  This
	 response MUST contain a Min-Expires header field that states
	 the minimum expiration interval the ESC is willing to honor.
	 jehan: NOT implemenetd

	 5. The ESC processes the published event state contained in the body
	 of the PUBLISH request.  If the content type of the request does
	 not match the event package, or is not understood by the ESC, the
	 ESC MUST reject the request with an appropriate response, such as
	 415 (Unsupported Media Type), and skip the remainder of the steps.

	 jehan: Already checked

	 *  The ESC stores the event state delivered in the body of the
	 PUBLISH request and identified by the associated entity-tag,
	 updating any existing event state for that entity-tag.  The
	 expiration value is set to the chosen expiration interval.

	 *  If the request has no message body and contained no entity-tag,
	 the ESC SHOULD reject the request with an appropriate response,
	 such as 400 (Invalid Request), and skip the remainder of the
	 steps.  Alternatively, in case either ESC local policy or the
	 event package has defined semantics for an initial publication
	 containing no message body, the ESC MAY accept it.
	 */
	if (!sipIfMatch && belle_sip_message_get_body_size(BELLE_SIP_MESSAGE(request)) <= 0)
		throw BELLESIP_SIGNALING_EXCEPTION(400) << "Publish without eTag must contain a body for request [" << std::hex
									   << (long)request << "]";

	// At that point, we are safe

	if (belle_sip_message_get_body_size(BELLE_SIP_MESSAGE(request)) > 0) {
		::std::unique_ptr<pidf::Presence> presence_body = NULL;
		try {
			istringstream data(belle_sip_message_get_body(BELLE_SIP_MESSAGE(request)));
			presence_body = parsePresence(data, xml_schema::Flags::dont_validate);
		} catch (const xml_schema::Exception &e) {
			ostringstream os;
			os << "Cannot parse body caused by [" << e << "]";
			// todo check error code
			throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", os.str().c_str())) << os.str();
		}

		// check entity
		belle_sip_uri_t *entity = belle_sip_uri_parse(presence_body->getEntity().c_str());
		if (!entity)
			throw BELLESIP_SIGNALING_EXCEPTION(400) << "Invalid presence entity [" << presence_body->getEntity()
										   << "] for request [" << request << "]";
		belle_sip_object_ref(entity); // initial ref = 0;

		belle_sip_header_from_t * from = belle_sip_message_get_header_by_type(request, belle_sip_header_from_t);
		if (!belle_sip_uri_equals(entity, belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(from))))
			throw BELLESIP_SIGNALING_EXCEPTION_1(400,belle_sip_header_create("Warning", "Entity must be same as From")) << "Invalid presence entity [" << presence_body->getEntity()
			<< "] for request [" << request << "] must be same as From";
			
		
		if (!(presenceInfo = getPresenceInfo(entity))) {
			presenceInfo = make_shared<PresentityPresenceInformation>(entity, *this, belle_sip_stack_get_main_loop(mStack));
			SLOGD << "New Presentity [" << *presenceInfo << "] created from PUBLISH";
			// for (const belle_sip_uri_t* : mPresenceInformations.keys())
			addPresenceInfo(presenceInfo);
		} else {
			SLOGD << "Presentity [" << *presenceInfo << "] found";
		}
		for (shared_ptr<PresentityPresenceInformationListener> listener : presenceInfo->getListeners()) {
			std::shared_ptr<PresentityPresenceInformation> toPresenceInfo = getPresenceInfo(listener->getTo());
			listener->enableExtendedNotify(toPresenceInfo && toPresenceInfo->findPresenceInfo(presenceInfo));
		}
		if (eTag.empty()) {
			eTag = presenceInfo->putTuples(presence_body->getTuple(), presence_body->getPerson().get(), expires);
		} else
			eTag = presenceInfo->updateTuples(presence_body->getTuple(), presence_body->getPerson().get(), eTag, expires);

		belle_sip_object_unref(entity);

	} else {
		/*
		 *  Else, the event state identified by the entity-tag is
		 refreshed, setting the expiration value to the chosen
		 expiration interval.

		 *  If the chosen expiration interval has a special value of "0",
		 the event state identified by the entity-tag MUST be
		 immediately removed.  The ESC MUST NOT store any event state as
		 a result of such a request.
		 */
		presenceInfo = getPresenceInfo(eTag);
		for (shared_ptr<PresentityPresenceInformationListener> listener : presenceInfo->getListeners()) {
			std::shared_ptr<PresentityPresenceInformation> toPresenceInfo = getPresenceInfo(listener->getTo());
			listener->enableExtendedNotify(toPresenceInfo && toPresenceInfo->findPresenceInfo(presenceInfo));
		}
		if (expires == 0) {
			if (presenceInfo)
				presenceInfo->removeTuplesForEtag(eTag);
			invalidateETag(eTag);
			/*else already expired*/
		} else {
			if (presenceInfo)
				eTag = presenceInfo->refreshTuplesForEtag(eTag, expires);
			else
				throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", "Unknown etag"));
		}
	}
	/*
	 The processing of the PUBLISH request MUST be atomic.  If internal
	 errors (such as the inability to access a back-end database) occur
	 before processing is complete, the publication MUST NOT succeed,
	 and the ESC MUST fail with an appropriate error response, such as
	 504 (Server Time-out), and skip the last step.

	 6. The ESC returns a 200 (OK) response.  The response MUST contain an
	 Expires header field indicating the expiration interval chosen by
	 the ESC.  The response MUST also contain a SIP-ETag header field
	 that contains a single entity-tag identifying the publication.
	 The ESC MUST generate a new entity-tag for each successful
	 publication, replacing any previous entity-tag associated with
	 that event state. The generated entity-tag MUST be unique from any
	 other entity-tags currently assigned to event state associated
	 with that Request-URI, and MUST be different from any entity-tag
	 assigned previously to event state for that Request-URI.  See
	 Section 8.3 for more information on the ESC handling of entity-
	 tags.
	 * */

	belle_sip_response_t *resp = belle_sip_response_create_from_request(request, 200);
	if (expires > 0) {
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp), belle_sip_header_create("SIP-ETag", eTag.c_str()));
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp),
									 (BELLE_SIP_HEADER(belle_sip_header_expires_create(expires))));
	}
	belle_sip_server_transaction_t *server_transaction =
		belle_sip_provider_create_server_transaction(mProvider, request);
	belle_sip_server_transaction_send_response(server_transaction, resp);
}

void PresenceServer::processSubscribeRequestEvent(const belle_sip_request_event_t *event) {
	belle_sip_request_t *request = belle_sip_request_event_get_request(event);

	/*
	 3.1.6.1. Initial SUBSCRIBE Transaction Processing

	 In no case should a SUBSCRIBE transaction extend for any longer than
	 the time necessary for automated processing.  In particular,
	 notifiers MUST NOT wait for a user response before returning a final
	 response to a SUBSCRIBE request.

	 This requirement is imposed primarily to prevent the non-INVITE
	 transaction timeout timer F (see [1]) from firing during the
	 SUBSCRIBE transaction, since interaction with a user would often
	 exceed 64*T1 seconds.

	 The notifier SHOULD check that the event package specified in the
	 "Event" header is understood.  If not, the notifier SHOULD return a
	 "489 Bad Event" response to indicate that the specified event/event
	 class is not understood.
	 */
	belle_sip_header_event_t *header_event = belle_sip_message_get_header_by_type(request, belle_sip_header_event_t);
	belle_sip_header_user_agent_t *user_agent = belle_sip_message_get_header_by_type(request, belle_sip_header_user_agent_t);
	bool bypass = FALSE;
	if(user_agent) {
		char cchar[100];
		belle_sip_header_user_agent_get_products_as_string(user_agent, cchar, sizeof(cchar));
		if(strcasestr(cchar, mBypass.c_str()) && strcmp(mBypass.c_str(), "false") != 0) {
			bypass = TRUE;
		}
	}
	if (!header_event)
		throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", "No Event package")) << "No Event package";

	if (strcmp("presence", belle_sip_header_event_get_package_name(header_event)) != 0)
		throw BELLESIP_SIGNALING_EXCEPTION(489) << "Unexpected Event package ["
									   << belle_sip_header_event_get_package_name(header_event) << "]";

	/*
	 The notifier SHOULD also perform any necessary authentication and
	 authorization per its local policy.  See section 3.1.6.3.

	 The notifier MAY also check that the duration in the "Expires" header
	 is not too small.  If and only if the expiration interval is greater
	 than zero AND smaller than one hour AND less than a notifier-
	 configured minimum, the notifier MAY return a "423 Interval too
	 small" error which contains a "Min-Expires" header field.  The "Min-
	 Expires" header field is described in SIP [1].

	 //jehan not checked

	 If the notifier is able to immediately determine that it understands
	 the event package, that the authenticated subscriber is authorized to
	 subscribe, and that there are no other barriers to creating the
	 subscription, it creates the subscription and a dialog (if
	 necessary), and returns a "200 OK" response (unless doing so would
	 reveal authorization policy in an undesirable fashion; see section
	 5.2.).

	 //jehan not checked yet


	 If the notifier cannot immediately create the subscription (e.g., it
	 needs to wait for user input for authorization, or is acting for
	 another node which is not currently reachable), or wishes to mask
	 authorization policy, it will return a "202 Accepted" response.  This
	 response indicates that the request has been received and understood,
	 but does not necessarily imply that the subscription has been
	 authorized yet.

	 When a subscription is created in the notifier, it stores the event
	 package name and the "Event" header "id" parameter (if present) as
	 part of the subscription information.

	 The "Expires" values present in SUBSCRIBE 200-class responses behave
	 in the same way as they do in REGISTER responses: the server MAY
	 shorten the interval, but MUST NOT lengthen it.

	 If the duration specified in a SUBSCRIBE message is unacceptably
	 short, the notifier may be able to send a 423 response, as
	 described earlier in this section.

	 200-class responses to SUBSCRIBE requests will not generally contain
	 any useful information beyond subscription duration; their primary
	 purpose is to serve as a reliability mechanism.  State information
	 will be communicated via a subsequent NOTIFY request from the
	 notifier.

	 The other response codes defined in SIP [1] may be used in response
	 to SUBSCRIBE requests, as appropriate.
	 */
	belle_sip_server_transaction_t *server_transaction =
		belle_sip_provider_create_server_transaction(mProvider, request);
	belle_sip_dialog_t *dialog = belle_sip_request_event_get_dialog(event);
	if (!dialog)
		dialog = belle_sip_provider_create_dialog(mProvider, BELLE_SIP_TRANSACTION(server_transaction));
	if (!dialog)
		throw BELLESIP_SIGNALING_EXCEPTION(481) << "Cannot create dialog from request ["<< request << "]";

	belle_sip_header_expires_t *headerExpires =
		belle_sip_message_get_header_by_type(request, belle_sip_header_expires_t);
	int expires;
	if (headerExpires)
		expires = belle_sip_header_expires_get_expires(headerExpires);
	else
		expires = 3600; // rfc3856, default value
	belle_sip_header_t *acceptEncodingHeader = belle_sip_message_get_header(BELLE_SIP_MESSAGE(request), "Accept-Encoding");
	switch (belle_sip_dialog_get_state(dialog)) {
		case BELLE_SIP_DIALOG_NULL: {
			belle_sip_header_supported_t *supported =
				belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request), belle_sip_header_supported_t);
			belle_sip_header_content_disposition_t *content_disposition = belle_sip_message_get_header_by_type(
				BELLE_SIP_MESSAGE(request), belle_sip_header_content_disposition_t);
			// first create the dialog
			belle_sip_response_t *resp = belle_sip_response_create_from_request(request, 200);
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp),
										 BELLE_SIP_HEADER(belle_sip_header_expires_create(expires)));

			// case of rfc5367 (list subscription with resource list in body
			if (supported && belle_sip_list_find_custom(belle_sip_header_supported_get_supported(supported),
														(belle_sip_compare_func)strcasecmp, "eventlist") &&
				content_disposition &&
				(strcasecmp(belle_sip_header_content_disposition_get_content_disposition(content_disposition),
							"recipient-list") == 0)) {

				SLOGD << "Subscribe for resource list "
					  << "for dialog [" << BELLE_SIP_OBJECT(dialog) << "]";

				shared_ptr<ListSubscription> listSubscription = make_shared<ListSubscription>(expires, server_transaction, mProvider); // will be release when last PresentityPresenceInformationListener is released
				if (acceptEncodingHeader) listSubscription->setAcceptEncodingHeader(acceptEncodingHeader);
				// send 200ok late to allow deeper anylise of request
				belle_sip_server_transaction_send_response(server_transaction, resp);

				belle_sip_dialog_set_application_data(dialog, new shared_ptr<Subscription> (listSubscription));
				for (shared_ptr<PresentityPresenceInformationListener> &listener : listSubscription->getListeners()) {
					listener->enableBypass(bypass); //expiration is handled by dialog
				}
#if 0
				for (shared_ptr<PresentityPresenceInformationListener> &listener : listSubscription->getListeners()) {
					addOrUpdateListener(listener); //expiration is handled by dialog
				}
#else
				addOrUpdateListeners(listSubscription->getListeners());
#endif
				listSubscription->notify(TRUE);

			} else {

				shared_ptr<PresentityPresenceInformationListener> subscription =
					make_shared<PresenceSubscription>(expires, belle_sip_request_get_uri(request), dialog, mProvider);
				belle_sip_dialog_set_application_data(dialog, new shared_ptr<Subscription>(dynamic_pointer_cast<Subscription>(subscription)));
				SLOGD << " setting sub pointer [" << belle_sip_dialog_get_application_data(dialog) << "] to dialog ["
					  << dialog << "]";
				// send 200ok late to allow deeper anylise of request
				belle_sip_server_transaction_send_response(server_transaction, resp);
				subscription->enableBypass(bypass);
				addOrUpdateListener(subscription, expires);
			}

			break;
		}
		case BELLE_SIP_DIALOG_CONFIRMED: {
			shared_ptr<Subscription> subscription;
			if (belle_sip_dialog_get_application_data(dialog)) {
				subscription= *static_cast<shared_ptr<Subscription>*>(belle_sip_dialog_get_application_data(dialog));
			}

			//			RFC 3265
			//			3.1.4.2. Refreshing of Subscriptions
			//
			//			 At any time before a subscription expires, the subscriber may refresh
			//			 the timer on such a subscription by sending another SUBSCRIBE request
			//			 on the same dialog as the existing subscription, and with the same
			//			 "Event" header "id" parameter (if one was present in the initial
			//			 subscription).  The handling for such a request is the same as for
			//			 the initial creation of a subscription except as described below.
			//
			//			 If the initial SUBSCRIBE message contained an "id" parameter on
			//			 the "Event" header, then refreshes of the subscription must also
			//			 contain an identical "id" parameter; they will otherwise be
			//			 considered new subscriptions in an existing dialog.
			//
			// FIXME not checked yet,

			//			 If a SUBSCRIBE request to refresh a subscription receives a "481"
			//			 response, this indicates that the subscription has been terminated
			//			 and that the subscriber did not receive notification of this fact.
			//			 In this case, the subscriber should consider the subscription
			//			 invalid.  If the subscriber wishes to re-subscribe to the state, he
			//			 does so by composing an unrelated initial SUBSCRIBE request with a
			//			 freshly-generated Call-ID and a new, unique "From" tag (see section
			//			 3.1.4.1.)

			if (!subscription  || subscription->getState() == Subscription::State::terminated) {
				throw BELLESIP_SIGNALING_EXCEPTION(481) << "Subscription [" << std::hex << subscription.get() << "] for dialog ["
											   << BELLE_SIP_OBJECT(dialog) << "] already in terminated state";
			}

			//			 If a SUBSCRIBE request to refresh a subscription fails with a non-481
			//			 response, the original subscription is still considered valid for the
			//			 duration of the most recently known "Expires" value as negotiated by
			//			 SUBSCRIBE and its response, or as communicated by NOTIFY in the
			//			 "Subscription-State" header "expires" parameter.
			//
			//			 Note that many such errors indicate that there may be a problem
			//			 with the network or the notifier such that no further NOTIFY
			//			 messages will be received.
			//

			belle_sip_response_t *resp = belle_sip_response_create_from_request(request, 200);
			belle_sip_server_transaction_send_response(server_transaction, resp);

			if (expires == 0) {
				removeSubscription(subscription);
			} else {
				// update expires
				subscription->increaseExpirationTime(expires);
				if (dynamic_pointer_cast<PresentityPresenceInformationListener>(subscription)) {
					shared_ptr<PresentityPresenceInformationListener> listener =
						dynamic_pointer_cast<PresentityPresenceInformationListener>(subscription);
					addOrUpdateListener(listener, expires);
				} else {
					// list subscription case
					shared_ptr<ListSubscription> listSubscription = dynamic_pointer_cast<ListSubscription>(subscription);
					for (shared_ptr<PresentityPresenceInformationListener> &listener : listSubscription->getListeners()) {
						listener->enableBypass(bypass); //expiration is handled by dialog
					}
#if 0
					for (shared_ptr<PresentityPresenceInformationListener> &listener : listSubscription->getListeners()) {
						addOrUpdateListener(listener, expires); //expiration is handled by dialog
					}
#else
					addOrUpdateListeners(listSubscription->getListeners(), expires);
#endif
				}
			}
			break;
		}

		default: {
			throw BELLESIP_SIGNALING_EXCEPTION(400) << "Unexpected request [" << std::hex << (long)request << "for dialog ["
										   << std::hex << (long)dialog << "in state ["
										   << belle_sip_dialog_state_to_string(belle_sip_dialog_get_state(dialog));
		}
	}
}

const std::shared_ptr<PresentityPresenceInformation> PresenceServer::getPresenceInfo(const string &eTag) const {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(eTag);
	if (presenceInformationsByEtagIt == mPresenceInformationsByEtag.end())
		return NULL;
	else
		return presenceInformationsByEtagIt->second;
}

void PresenceServer::addPresenceInfo(const std::shared_ptr<PresentityPresenceInformation> &presenceInfo) {

	if (getPresenceInfo(presenceInfo->getEntity())) {
		throw FLEXISIP_EXCEPTION << "Presence information element already exist for" << presenceInfo;
	}
	mPresenceInformations[presenceInfo->getEntity()] = presenceInfo;
	for (auto& listener : mPresenceInfoObservers) {
		listener->onNewPresenceInfo(presenceInfo);
	}
}

void PresenceServer::addPresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver> &observer) {
	mPresenceInfoObservers.push_back(observer); 
}

void PresenceServer::removePresenceInfoObserver(const std::shared_ptr<PresenceInfoObserver> &listener) {
	auto it = find(mPresenceInfoObservers.begin(), mPresenceInfoObservers.end(), listener);
	if (it != mPresenceInfoObservers.end()) {
		mPresenceInfoObservers.erase(it);
	} else {
		SLOGW << "No such listener " << listener << " registered, ignoring.";
	}
}



std::shared_ptr<PresentityPresenceInformation> PresenceServer::getPresenceInfo(const belle_sip_uri_t *identity) const {
	auto presenceEntityInformationIt = mPresenceInformations.find(identity);
	if (presenceEntityInformationIt == mPresenceInformations.end())
		return NULL;
	else
		return presenceEntityInformationIt->second;
}

void PresenceServer::invalidateETag(const string &eTag) {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(eTag);
	if (presenceInformationsByEtagIt != mPresenceInformationsByEtag.end()) {
		const std::shared_ptr<PresentityPresenceInformation> presenceInfo = presenceInformationsByEtagIt->second;
		if (presenceInfo->getNumberOfListeners() == 0  && presenceInfo->getNumberOfInformationElements() == 0) {
			SLOGD << "Presentity [" << *presenceInfo << "] no longuer referenced by any SUBSCRIBE nor PUBLISH, removing";
			mPresenceInformations.erase(presenceInfo->getEntity());
		}
		mPresenceInformationsByEtag.erase(eTag);
		SLOGD <<"Etag manager size ["<<mPresenceInformationsByEtag.size()<<"]";
	}

}
void PresenceServer::modifyEtag(const string &oldEtag, const string &newEtag) {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(oldEtag);
	if (presenceInformationsByEtagIt == mPresenceInformationsByEtag.end())
		throw FLEXISIP_EXCEPTION << "Unknown etag [" << oldEtag << "]";
	mPresenceInformationsByEtag[newEtag] = presenceInformationsByEtagIt->second;
	mPresenceInformationsByEtag.erase(oldEtag);
}
void PresenceServer::addEtag(const std::shared_ptr<PresentityPresenceInformation> &info,
							 const string &etag) {
	auto presenceInformationsByEtagIt = mPresenceInformationsByEtag.find(etag);
	if (presenceInformationsByEtagIt != mPresenceInformationsByEtag.end())
		throw FLEXISIP_EXCEPTION << "Already existing etag [" << etag << "] use PresenceServer::modifyEtag instead ";
	mPresenceInformationsByEtag[etag] = info;
	SLOGD <<"Etag manager size ["<<mPresenceInformationsByEtag.size()<<"]";
}

void PresenceServer::addOrUpdateListener(shared_ptr<PresentityPresenceInformationListener> &listener) {
	addOrUpdateListener(listener,-1);
}
void PresenceServer::addOrUpdateListener(shared_ptr<PresentityPresenceInformationListener> &listener, int expires) {
	std::shared_ptr<PresentityPresenceInformation> presenceInfo = getPresenceInfo(listener->getPresentityUri());
	
	if (presenceInfo == NULL) {
		/*no information available yet, but creating entry to be able to register subscribers*/
		presenceInfo = make_shared<PresentityPresenceInformation>(listener->getPresentityUri(), *this,
															 belle_sip_stack_get_main_loop(mStack));
		SLOGD << "New Presentity [" << *presenceInfo << "] created from SUBSCRIBE";
		addPresenceInfo(presenceInfo);
	}
	
	//notify observers that a listener is added or updated
	for (auto& listener : mPresenceInfoObservers) {
		listener->onListenerEvent(presenceInfo);
	}

	std::shared_ptr<PresentityPresenceInformation> toPresenceInfo = getPresenceInfo(listener->getTo());
	presenceInfo->addListenerIfNecessary(listener);
	listener->enableExtendedNotify(toPresenceInfo && toPresenceInfo->findPresenceInfo(presenceInfo));

	if (expires > 0)
		presenceInfo->addOrUpdateListener(listener, expires);
	else
		presenceInfo->addOrUpdateListener(listener);

}

void PresenceServer::addOrUpdateListeners(list<shared_ptr<PresentityPresenceInformationListener>> &listeners) {
	addOrUpdateListeners(listeners,-1);
}
void PresenceServer::addOrUpdateListeners(list<shared_ptr<PresentityPresenceInformationListener>> &listeners, int expires) {
	list<std::shared_ptr<PresentityPresenceInformation>> presenceInfos;
	for (shared_ptr<PresentityPresenceInformationListener> &listener : listeners) {
		std::shared_ptr<PresentityPresenceInformation> presenceInfo = getPresenceInfo(listener->getPresentityUri());
		if (presenceInfo == NULL) {
			/*no information available yet, but creating entry to be able to register subscribers*/
			presenceInfo = make_shared<PresentityPresenceInformation>(listener->getPresentityUri(), *this,
																  belle_sip_stack_get_main_loop(mStack));
			SLOGD << "New Presentity [" << *presenceInfo << "] created from SUBSCRIBE";
			addPresenceInfo(presenceInfo);
		}

		std::shared_ptr<PresentityPresenceInformation> toPresenceInfo = getPresenceInfo(listener->getTo());
		presenceInfo->addListenerIfNecessary(listener);
		listener->enableExtendedNotify(toPresenceInfo && toPresenceInfo->findPresenceInfo(presenceInfo));

		if (expires > 0)
			presenceInfo->addOrUpdateListener(listener, expires);
		else
			presenceInfo->addOrUpdateListener(listener);

		presenceInfos.push_back(presenceInfo);
	}
	
	//notify observers that a listener is added or updated
	for (auto& listener : mPresenceInfoObservers) {
			listener->onListenerEvents(presenceInfos);
	}
}
void PresenceServer::removeListener(const shared_ptr<PresentityPresenceInformationListener> &listener) {
	const std::shared_ptr<PresentityPresenceInformation> presenceInfo = getPresenceInfo(listener->getPresentityUri());
	if (presenceInfo) {
		presenceInfo->removeListener(listener);
		if (presenceInfo->getNumberOfListeners() == 0  && presenceInfo->getNumberOfInformationElements() == 0) {
			SLOGD << "Presentity [" << *presenceInfo << "] no longer referenced by any SUBSCRIBE nor PUBLISH, removing";
			mPresenceInformations.erase(presenceInfo->getEntity());
		}
	} else
		SLOGI << "No presence info for this entity [" << listener->getPresentityUri() << "]/[" << std::hex
			  << (long)&listener << "]";
}

void PresenceServer::removeSubscription(shared_ptr<Subscription> &subscription) throw() {
	subscription->setState(Subscription::State::terminated);
	if (dynamic_pointer_cast<PresenceSubscription>(subscription)) {
		shared_ptr<PresentityPresenceInformationListener> listener =
			dynamic_pointer_cast<PresentityPresenceInformationListener >(subscription);
		removeListener(listener);
	} else {
		// list subscription case
		shared_ptr<ListSubscription> listSubscription = dynamic_pointer_cast<ListSubscription >(subscription);
		for (shared_ptr<PresentityPresenceInformationListener> listener : listSubscription->getListeners()) {
			removeListener(listener);
		}
		listSubscription->notify(0); // to trigger final notify
		//delete listSubscription;
	}
}

belle_sip_main_loop_t* PresenceServer::getBelleSipMainLoop() {
	return belle_sip_stack_get_main_loop(this->mStack);
}
