/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "presence-server.hh"

#include <algorithm>
#include <string.h>

#include <belle-sip/belle-sip.h>
#if ENABLE_SOCI
#include <soci/mysql/soci-mysql.h>
#endif

#include "flexisip/configmanager.hh"

#include "bellesip-signaling-exception.hh"
#include "exceptions/bad-configuration.hh"
#include "exceptions/presence-server.hh"
#include "observers/presence-longterm.hh"
#include "presence/presentity/presentity-manager.hh"
#include "presence/presentity/presentity-presence-information.hh"
#include "presence/subscription/subscription.hh"
#include "subscription/body-list-subscription.hh"
#include "utils/belle-sip-utils.hh"
#include "utils/thread/auto-thread-pool.hh"
#include "xml/pidf+xml.hh"
#include "xml/resource-lists.hh"

#if ENABLE_SOCI
#include "subscription/external-list-subscription.hh"
#endif

using namespace flexisip;
using namespace std;

unsigned int PresenceServer::sLastActivityRetentionMs;

namespace {
// Statically define default configuration items
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        Boolean,
	        "enabled",
	        "Enable presence server",
	        "true",
	    },
	    {
	        StringList,
	        "transports",
	        "List of white space separated SIP URIs where the presence server must listen. Must not be tls.",
	        "sip:127.0.0.1:5065;transport=tcp",
	    },
	    {
	        DurationS,
	        "expires",
	        "Default expires of PUBLISH request.",
	        "600",
	    },
	    {
	        Integer,
	        "notify-limit",
	        "Max number of presentity sent in a single NOTIFY by default.",
	        "200",
	    },
	    {
	        Boolean,
	        "long-term-enabled",
	        "Enable long-term presence notifies",
	        "false",
	    },
	    {
	        String,
	        "rls-database-connection",
	        "Soci connection string for the resource list database.",
	        "",
	    },
	    {
	        String,
	        "rls-database-request",
	        "SQL request to obtain the list of the users corresponding to an resource list subscription.\n"
	        "Named parameters are:\n"
	        " * ':from' : the URI of the sender of the SUBSCRIBE. (mandatory)\n"
	        " * ':to' : the URI of the users list which the sender want to subscribe to. (mandatory)\n",
	        "",
	    },
	    {
	        Integer,
	        "rls-database-max-thread",
	        "Max number of threads.",
	        "50",
	    },
	    {
	        Integer,
	        "rls-database-max-thread-queue-size",
	        "Max legnth of threads queue.",
	        "50",
	    },
	    {
	        String,
	        "soci-user-with-phone-request",
	        "Soci SQL request used to obtain the username associated with a phone alias.\n"
	        "The string MUST contains the ':phone' keyword which will be replaced by the phone number to look for.\n"
	        "The result of the request is a 1x1 table containing the name of the user associated with the phone "
	        "number.\n"
	        "\n"
	        "Example: select login from accounts where phone = :phone ",
	        "",
	    },
	    {
	        String,
	        "soci-users-with-phones-request",
	        "Same as 'soci-user-with-phone-request' but allows to fetch several users by a unique SQL request.\n"
	        "The string MUST contains the ':phones' keyword which will be replaced by the list of phone numbers to "
	        "look for. Each element of the list is seperated by a comma character and is protected by simple quotes "
	        "(e.g. '0336xxxxxxxx','0337yyyyyyyy','034zzzzzzzzz').\n"
	        "If you use phone number linked accounts you'll need to select login, domain, phone in your request for "
	        "flexisip to work.\n"
	        "Example: select login, domain, phone from accounts where phone in (:phones)",
	        "",
	    },
	    {
	        Integer,
	        "max-presence-elements",
	        "Maximum number of presence element by identity saved in memory.",
	        "10",
	    },

	    // Hidden parameters
	    {
	        String,
	        "bypass-condition",
	        "If user agent contains it, can bypass extended notifiy verification.",
	        "false",
	    },
	    {
	        Boolean,
	        "leak-detector",
	        "Enable belle-sip leak detector",
	        "false",
	    },

	    // Deprecated parameters
	    {
	        String,
	        "soci-connection-string",
	        "Connection string to SOCI.",
	        "",
	    },
	    {
	        String,
	        "external-list-subscription-request",
	        "Soci SQL request to execute to obtain the list of the users corresponding to an external subscription.\n"
	        "Named parameters are:\n"
	        " * ':from' : the URI of the sender of the SUBSCRIBE.\n"
	        " * ':to' : the URI of the users list which the sender want to subscribe to.\n"
	        "The use of the :from & :to parameters are mandatory.",
	        "",
	    },
	    {
	        Integer,
	        "max-thread",
	        "Max number of threads.",
	        "50",
	    },
	    {
	        Integer,
	        "max-thread-queue-size",
	        "Max legnth of threads queue.",
	        "50",
	    },
	    {
	        Integer,
	        "last-activity-retention-time",
	        "Duration in milliseconds during which the last activity is kept in memory. Default is 1 day.",
	        "86400000",
	    },
	    config_item_end,
	};

	auto s = root.addChild(make_unique<GenericStruct>("presence-server", "Flexisip presence server parameters.", 0));
	s->addChildrenValues(items);

	s->get<ConfigString>("bypass-condition")->setExportable(false);
	s->get<ConfigBoolean>("leak-detector")->setExportable(false);

	auto sociConnectionString = s->get<ConfigString>("soci-connection-string");
	sociConnectionString->setDeprecated({
	    "2020-06-02",
	    "2.0.0",
	    "Renamed into 'rls-database-connection'",
	});
	s->get<ConfigString>("rls-database-connection")->setFallback(*sociConnectionString);

	auto externalListSubscriptionRequest = s->get<ConfigString>("external-list-subscription-request");
	externalListSubscriptionRequest->setDeprecated({
	    "2020-06-02",
	    "2.0.0",
	    "Renamed into 'rls-database-request'",
	});
	s->get<ConfigString>("rls-database-request")->setFallback(*externalListSubscriptionRequest);

	auto maxThread = s->get<ConfigInt>("max-thread");
	maxThread->setDeprecated({
	    "2020-06-02",
	    "2.0.0",
	    "Renamed into 'rls-database-max-thread'",
	});
	s->get<ConfigInt>("rls-database-max-thread")->setFallback(*maxThread);

	auto maxThreadQueueSize = s->get<ConfigInt>("max-thread-queue-size");
	maxThreadQueueSize->setDeprecated({
	    "2020-06-02",
	    "2.0.0",
	    "Renamed into 'rls-database-max-thread-queue-size'",
	});
	s->get<ConfigInt>("rls-database-max-thread-queue-size")->setFallback(*maxThreadQueueSize);

	s->createStatPair("count-presence-presentity", "Number of PresentityPresenceInformation");
	s->createStatPair("count-presence-element-map", "Number of PresenceInformationElementMap");
	s->createStatPair("count-presence-element", "Number of PresenceInformationElement");

	s->createStatPair("count-presence-subscription", "Number of PresenceSubscription");
	s->createStatPair("count-presence-body-list-subscription", "Number of BodyListSubscription");
	s->createStatPair("count-presence-external-list-subscription", "Number of ExternalListSubscription");
});
} // namespace

PresenceServer::PresenceServer(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg)
    : ServiceServer{root}, mConfigManager(cfg) {
	auto* config = mConfigManager->getRoot()->get<GenericStruct>("presence-server");
	/*Enabling leak detector should be done asap.*/
	belle_sip_object_enable_leak_detector(config->get<ConfigBoolean>("leak-detector")->read());
	mStack = belle_sip_stack_new(nullptr);

	mPresenceStats.countPresenceSub = config->getStatPairPtr("count-presence-subscription");
	mPresenceStats.countBodyListSub = config->getStatPairPtr("count-presence-body-list-subscription");
	mPresenceStats.countExternalListSub = config->getStatPairPtr("count-presence-external-list-subscription");

	mPresenceStats.countPresencePresentity = config->getStatPairPtr("count-presence-presentity");
	mPresenceStats.countPresenceElement = config->getStatPairPtr("count-presence-element");
	mPresenceStats.countPresenceElementMap = config->getStatPairPtr("count-presence-element-map");
	mPresentityManager = std::make_unique<PresentityManager>(mStack, mPresenceStats,
	                                                         config->get<ConfigInt>("max-presence-elements")->read());

	mProvider = belle_sip_stack_create_provider(mStack, nullptr);
	mMaxPresenceInfoNotifiedAtATime = config->get<ConfigInt>("notify-limit")->read();

	xercesc::XMLPlatformUtils::Initialize();

	belle_sip_listener_callbacks_t listener_callbacks;
	memset(&listener_callbacks, 0, sizeof(listener_callbacks));
	listener_callbacks.process_dialog_terminated =
	    (void (*)(void*, const belle_sip_dialog_terminated_event_t*))PresenceServer::processDialogTerminated;
	listener_callbacks.process_io_error =
	    (void (*)(void*, const belle_sip_io_error_event_t*))PresenceServer::processIoError;
	listener_callbacks.process_request_event =
	    (void (*)(void*, const belle_sip_request_event_t*))PresenceServer::processRequestEvent;
	listener_callbacks.process_response_event =
	    (void (*)(void*, const belle_sip_response_event_t*))PresenceServer::processResponseEvent;
	listener_callbacks.process_timeout =
	    (void (*)(void*, const belle_sip_timeout_event_t*))PresenceServer::processTimeout;
	listener_callbacks.process_transaction_terminated =
	    (void (*)(void*, const belle_sip_transaction_terminated_event_t*))PresenceServer::processTransactionTerminated;
	mListener = belle_sip_listener_create_from_callbacks(&listener_callbacks, this);
	belle_sip_provider_add_sip_listener(mProvider, mListener);

	PresenceServer::sLastActivityRetentionMs = config->get<ConfigInt>("last-activity-retention-time")->read();

	mDefaultExpires =
	    chrono::duration_cast<chrono::seconds>(config->get<ConfigDuration<chrono::seconds>>("expires")->read()).count();
	mBypass = config->get<ConfigString>("bypass-condition")->read();
	mEnabled = config->get<ConfigBoolean>("enabled")->read();
	mRequest = config->get<ConfigString>("rls-database-request")->read();

	if (mRequest.empty()) return;

	int maxThreads = config->get<ConfigInt>("rls-database-max-thread")->read();
	int maxQueueSize = config->get<ConfigInt>("rls-database-max-thread-queue-size")->read();

	mThreadPool = make_unique<AutoThreadPool>(maxThreads, maxQueueSize);
#if ENABLE_SOCI
	const string& connectionString = config->get<ConfigString>("rls-database-connection")->read();
	mConnPool = new soci::connection_pool(maxThreads);

	try {
		for (size_t i = 0; i < size_t(maxThreads); i++) {
			mConnPool->at(i).open("mysql", connectionString);
		}
	} catch (soci::mysql_soci_error const& e) {
		LOGE << "Connection pool open MySQL error [" << e.err_num_ << "]: " << e.what();
	} catch (exception const& e) {
		LOGE << "Connection pool open error: " << e.what();
	}
#endif
}

static void remove_listening_point(belle_sip_listening_point_t* lp, belle_sip_provider_t* prov) {
	belle_sip_provider_remove_listening_point(prov, lp);
}

PresenceServer::~PresenceServer() {
	belle_sip_provider_clean_channels(mProvider);
	const belle_sip_list_t* lps = belle_sip_provider_get_listening_points(mProvider);
	belle_sip_list_t* tmp_list = belle_sip_list_copy(lps);
	belle_sip_list_for_each2(tmp_list, (void (*)(void*, void*))remove_listening_point, mProvider);
	belle_sip_list_free(tmp_list);

	// must be done before cleaning xerces and mStack
	mPresentityManager.reset();

	belle_sip_object_unref(mProvider);
	belle_sip_object_unref(mStack);
	belle_sip_object_unref(mListener);

	xercesc::XMLPlatformUtils::Terminate();
	belle_sip_object_dump_active_objects();
	belle_sip_object_flush_active_objects();

#if ENABLE_SOCI
	if (mConnPool) delete mConnPool;
#endif
	LOGD << "Destroyed instance";
}

void PresenceServer::_init() {
	if (!mEnabled) return;
	const auto* cr = mConfigManager->getRoot();

	const auto* longTermEnabledConfig =
	    cr->get<GenericStruct>("presence-server")->get<ConfigBoolean>("long-term-enabled");
	auto longTermEnabled = longTermEnabledConfig->read();

	const auto& dbImplementation =
	    cr->get<GenericStruct>("module::Authentication")->get<ConfigString>("db-implementation")->read();
	const auto* getUsersWithPhonesRequestParam =
	    cr->get<GenericStruct>("presence-server")->get<ConfigString>("soci-users-with-phones-request");
	const auto* getUserWithPhoneRequestParam =
	    cr->get<GenericStruct>("presence-server")->get<ConfigString>("soci-user-with-phone-request");
	const auto& getUsersWithPhonesRequest = getUsersWithPhonesRequestParam->read();
	const auto& getUserWithPhoneRequest = getUserWithPhoneRequestParam->read();
	auto userDbIsProperlySet =
	    dbImplementation == "file" || !getUsersWithPhonesRequest.empty() || !getUserWithPhoneRequest.empty();

	if (longTermEnabledConfig->isDefault() && userDbIsProperlySet) {
		throw BadConfiguration{"the default value of '" + longTermEnabledConfig->getCompleteName() +
		                       "' parameter has changed since Flexisip 2.0.0, please explicitly set the value for this "
		                       "parameter or unset '" +
		                       getUserWithPhoneRequestParam->getCompleteName() + "' and '" +
		                       getUsersWithPhonesRequestParam->getCompleteName() + "' to remove this error"};
	}
	if (longTermEnabled && !userDbIsProperlySet) {
		throw BadConfiguration{
		    "unable to start presence server, neither '" + getUserWithPhoneRequestParam->getCompleteName() + "' or '" +
		    getUsersWithPhonesRequestParam->getCompleteName() + "' are set whereas long-term presence is enabled"};
	}

	auto transports = cr->get<GenericStruct>("presence-server")->get<ConfigStringList>("transports")->read();

	for (const auto& transport : transports) {
		if (transport.find("sips") != string::npos || transport.find("transport=tls") != string::npos)
			throw BadConfiguration{"unable to start presence server, TLS transports are not supported"};

		auto* uri = belle_sip_uri_parse(transport.c_str());
		if (uri) {
			auto* lp = belle_sip_stack_create_listening_point(
			    mStack, belle_sip_uri_get_host(uri), belle_sip_uri_get_listening_port(uri),
			    belle_sip_uri_get_transport_param(uri) ? belle_sip_uri_get_transport_param(uri) : "udp");
			belle_sip_object_unref(uri);
			if (belle_sip_provider_add_listening_point(mProvider, lp))
				throw FlexisipException{"cannot add lp for [" + transport + "]"};
		}
	}
}

void PresenceServer::_run() {
	belle_sip_main_loop_sleep(belle_sip_stack_get_main_loop(mStack), 0);
}

std::unique_ptr<AsyncCleanup> PresenceServer::_stop() {
	return nullptr;
}

void PresenceServer::processDialogTerminated(PresenceServer* thiz, const belle_sip_dialog_terminated_event_t* event) {
	belle_sip_dialog_t* dialog = belle_sip_dialog_terminated_event_get_dialog(event);
	auto sub = getSubscription(dialog);
	if (dynamic_pointer_cast<ListSubscription>(sub)) {
		LOGD << "Subscription [" << sub << "] has expired";
		thiz->removeSubscription(sub);
	} // else  nothing to be done for now because expire is performed at SubscriptionLevel
}
void PresenceServer::processIoError(PresenceServer*, const belle_sip_io_error_event_t*) {
	LOGD << "Not implemented yet";
}
void PresenceServer::processRequestEvent(PresenceServer* thiz, const belle_sip_request_event_t* event) {
	belle_sip_request_t* request = belle_sip_request_event_get_request(event);
	belle_sip_response_t* resp = nullptr;
	try {
		if (strcmp(belle_sip_request_get_method(request), "PUBLISH") == 0) {
			thiz->processPublishRequestEvent(event);

		} else if (strcmp(belle_sip_request_get_method(request), "SUBSCRIBE") == 0) {
			thiz->processSubscribeRequestEvent(event);

		} else {
			LOGI << "Unsupported method: " << belle_sip_request_get_method(request);
			throw BelleSipSignalingException{405, BELLE_SIP_HEADER(belle_sip_header_allow_create("PUBLISH"))};
		}
	} catch (const BelleSipSignalingException& e) {
		resp = belle_sip_response_create_from_request(request, e.getStatusCode());
		for (belle_sip_header_t* header : e.getHeaders())
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp), header);
	} catch (const PresenceServerException& e) {
		// Catch non-critical exceptions (however, request processing needed to be stopped)
		LOGI << "Interrupted request processing: " << e.what();
		resp = belle_sip_response_create_from_request(request, 500);
	} catch (const exception& e) {
		LOGE << "Caught an unexpected exception: " << e.what();
		resp = belle_sip_response_create_from_request(request, 500);
	}
	if (resp) {
		belle_sip_server_transaction_t* tr =
		    (belle_sip_server_transaction_t*)belle_sip_object_data_get((belle_sip_object_t*)request, "my-transaction");
		if (tr) {
			belle_sip_server_transaction_send_response(tr, resp);
		} else {
			belle_sip_provider_send_response(thiz->mProvider, resp);
		}
	}
}
void PresenceServer::processResponseEvent(PresenceServer*, const belle_sip_response_event_t* event) {
	belle_sip_response_t* resp = belle_sip_response_event_get_response(event);
	int code = belle_sip_response_get_status_code(resp);
	if (code == 407) {
		LOGE << "Presence server being challenged by Flexisip probably means that Flexisip is misconfigured, this "
		        "server should be a trusted host";
	} else {
		LOGD << "Not handled yet for " << code << ": " << belle_sip_response_get_reason_phrase(resp);
	}
}
void PresenceServer::processTimeout(PresenceServer* thiz, const belle_sip_timeout_event_t* event) {
	belle_sip_client_transaction_t* client = belle_sip_timeout_event_get_client_transaction(event);
	auto subscription = client ? getSubscription(client) : nullptr;
	if (subscription) {
		thiz->removeSubscription(subscription);
		LOGD << "Removing subscription [" << subscription << "] because no response received";
	}
}
void PresenceServer::processTransactionTerminated(PresenceServer*,
                                                  const belle_sip_transaction_terminated_event_t* event) {
	belle_sip_client_transaction_t* client = belle_sip_transaction_terminated_event_get_client_transaction(event);
	auto sub = client ? getSubscription(client) : nullptr;
	if (sub) {
		sub->mCurrentTransaction = nullptr;
	}
}

void PresenceServer::processPublishRequestEvent(const belle_sip_request_event_t* event) {
	belle_sip_request_t* request = belle_sip_request_event_get_request(event);
	shared_ptr<PresentityPresenceInformation> presenceInfo;

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
	belle_sip_header_t* eventHeader = belle_sip_message_get_header(BELLE_SIP_MESSAGE(request), "Event");
	if (!eventHeader) {
		LOGI << "No sip event for request [" << hex << (long)request << "]";
		throw BelleSipSignalingException{489};
	}

	if (strcasecmp(belle_sip_header_get_unparsed_value(eventHeader), "Presence") != 0) {
		LOGI << "Unsupported event [" << belle_sip_header_get_unparsed_value(eventHeader) << "] for request [" << hex
		     << (long)request << "]";
		throw BelleSipSignalingException{489};
	}

	/*
	 3. The ESC examines the SIP-If-Match header field of the PUBLISH
	 request for the presence of a request precondition.
	 */
	belle_sip_header_t* sipIfMatch = belle_sip_message_get_header(BELLE_SIP_MESSAGE(request), "SIP-If-Match");
	belle_sip_header_content_type_t* contentType =
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

			LOGI << "Unsupported media type ["
			     << (contentType ? belle_sip_header_content_type_get_type(contentType) : "<unknown>") << "/"
			     << (contentType ? belle_sip_header_content_type_get_subtype(contentType) : "<unknown>") << "]";
			throw BelleSipSignalingException{415, belle_sip_header_create("Accept", "application/pidf+xml")};
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
		if (!mPresentityManager->getPresenceInfo(eTag)) {
			LOGI << "Unknown ETag [" << eTag << "] for request [" << hex << (long)request << "]";
			throw BelleSipSignalingException{412};
		}
	}
	belle_sip_header_expires_t* headerExpires =
	    belle_sip_message_get_header_by_type(request, belle_sip_header_expires_t);
	int expires;
	/*
	 * 4. The ESC processes the Expires header field value from the PUBLISH request.
	 *   If the request has an Expires header field, that value MUST be taken as the requested expiration.
	 *   Else, a locally-configured default value MUST be taken as the requested expiration.
	 *
	 */
	expires = headerExpires ? belle_sip_header_expires_get_expires(headerExpires) : mDefaultExpires;

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
	if (!sipIfMatch && belle_sip_message_get_body_size(BELLE_SIP_MESSAGE(request)) <= 0) {
		LOGI << "Publish without ETag must contain a body for request [" << hex << (long)request << "]";
		throw BelleSipSignalingException{400};
	}

	// At that point, we are safe

	if (belle_sip_message_get_body_size(BELLE_SIP_MESSAGE(request)) > 0) {
		unique_ptr<Xsd::Pidf::Presence> presenceBody = nullptr;
		try {
			istringstream data(belle_sip_message_get_body(BELLE_SIP_MESSAGE(request)));
			presenceBody = Xsd::Pidf::parsePresence(data, Xsd::XmlSchema::Flags::dont_validate);
		} catch (const Xsd::XmlSchema::Exception& e) {
			stringstream error;
			error << "Cannot parse body: " << e.what();
			LOGI << error.str();
			// todo check error code
			throw BelleSipSignalingException{400, belle_sip_header_create("Warning", error.str().c_str())};
		}

		// check entity
		bellesip::shared_ptr<belle_sip_uri_t> entity{belle_sip_uri_parse(presenceBody->getEntity().c_str())};
		if (!entity) {
			LOGI << "Invalid presence entity [" << presenceBody->getEntity() << "] for request [" << request << "]";
			throw BelleSipSignalingException{400};
		}

		belle_sip_header_from_t* from = belle_sip_message_get_header_by_type(request, belle_sip_header_from_t);
		if (!belle_sip_uri_equals(entity.get(), belle_sip_header_address_get_uri(BELLE_SIP_HEADER_ADDRESS(from)))) {
			LOGI << "Invalid presence entity [" << presenceBody->getEntity() << "] for request [" << request
			     << "]: must be same as From";
			throw BelleSipSignalingException{400, belle_sip_header_create("Warning", "Entity must be same as From")};
		}

		eTag = mPresentityManager->handlePublishFor(entity.get(), eTag, std::move(presenceBody), expires);
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
		eTag = mPresentityManager->handlePublishRefreshedFor(eTag, expires);
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

	belle_sip_response_t* resp = belle_sip_response_create_from_request(request, 200);
	if (expires > 0) {
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp), belle_sip_header_create("SIP-ETag", eTag.c_str()));
		belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp),
		                             (BELLE_SIP_HEADER(belle_sip_header_expires_create(expires))));
	}
	belle_sip_server_transaction_t* server_transaction =
	    belle_sip_provider_create_server_transaction(mProvider, request);
	belle_sip_server_transaction_send_response(server_transaction, resp);
}

void PresenceServer::processSubscribeRequestEvent(const belle_sip_request_event_t* event) {
	belle_sip_request_t* request = belle_sip_request_event_get_request(event);

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
	auto headerEvent = belle_sip_message_get_header_by_type(request, belle_sip_header_event_t);
	auto userAgent = belle_sip_message_get_header_by_type(request, belle_sip_header_user_agent_t);
	auto bypass = false;
	if (userAgent) {
		char userAgentStr[100];
		belle_sip_header_user_agent_get_products_as_string(userAgent, userAgentStr, sizeof(userAgentStr));
		bypass = mBypass != "false" && strcasestr(userAgentStr, mBypass.c_str()) != nullptr;
	}
	if (!headerEvent) {
		LOGI << "No event package";
		throw BelleSipSignalingException{400, belle_sip_header_create("Warning", "No Event package")};
	}

	if (strcmp("presence", belle_sip_header_event_get_package_name(headerEvent)) != 0) {
		LOGI << "Unexpected event package [" << belle_sip_header_event_get_package_name(headerEvent) << "]";
		throw BelleSipSignalingException{489};
	}

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
	belle_sip_server_transaction_t* server_transaction =
	    belle_sip_provider_create_server_transaction(mProvider, request);
	belle_sip_object_data_set((belle_sip_object_t*)request, "my-transaction", server_transaction, nullptr);
	bellesip::shared_ptr<belle_sip_dialog_t> dialog{belle_sip_request_event_get_dialog(event)};
	if (!dialog) dialog.reset(belle_sip_provider_create_dialog(mProvider, BELLE_SIP_TRANSACTION(server_transaction)));

	if (!dialog) {
		LOGI << "Cannot create dialog from request [" << request << "]";
		throw BelleSipSignalingException{481};
	}

	belle_sip_header_expires_t* headerExpires =
	    belle_sip_message_get_header_by_type(request, belle_sip_header_expires_t);
	int expires = headerExpires ? belle_sip_header_expires_get_expires(headerExpires) : 3600; // rfc3856, default value
	belle_sip_header_t* acceptEncodingHeader =
	    belle_sip_message_get_header(BELLE_SIP_MESSAGE(request), "Accept-Encoding");
	switch (belle_sip_dialog_get_state(dialog.get())) {
		case BELLE_SIP_DIALOG_NULL: {
			belle_sip_header_supported_t* supported =
			    belle_sip_message_get_header_by_type(BELLE_SIP_MESSAGE(request), belle_sip_header_supported_t);
			belle_sip_header_content_disposition_t* content_disposition = belle_sip_message_get_header_by_type(
			    BELLE_SIP_MESSAGE(request), belle_sip_header_content_disposition_t);
			// first create the dialog
			bellesip::shared_ptr<belle_sip_response_t> resp{belle_sip_response_create_from_request(request, 200)};
			belle_sip_message_add_header(BELLE_SIP_MESSAGE(resp.get()),
			                             BELLE_SIP_HEADER(belle_sip_header_expires_create(expires)));

			// List subscription
			if (supported && belle_sip_list_find_custom(belle_sip_header_supported_get_supported(supported),
			                                            (belle_sip_compare_func)strcasecmp, "eventlist")) {
				LOGD << "Subscribe to resource list for dialog [" << BELLE_SIP_OBJECT(dialog.get()) << "]";
				// will be release when last PresentityPresenceInformationListener is released
				shared_ptr<ListSubscription> listSubscription;
				belle_sip_header_content_type_t* contentType =
				    belle_sip_message_get_header_by_type(request, belle_sip_header_content_type_t);
				auto listAvailableLambda = [this, bypass, acceptEncodingHeader, server_transaction, resp,
				                            wDialog = bellesip::weak_ptr<belle_sip_dialog_t>{dialog}](
				                               shared_ptr<ListSubscription> listSubscription) {
					auto dialog = wDialog.lock();
					if (!dialog) {
						LOGI_CTX(mLogPrefix, "processSubscribeRequestEvent")
						    << "Dialog for ListSubscription[" << listSubscription
						    << "] no more exists: aborting list subscription";
						return;
					}

					if (acceptEncodingHeader) listSubscription->setAcceptEncodingHeader(acceptEncodingHeader);

					if (getSubscription(dialog.get()) == nullptr) {
						setSubscription(dialog.get(), listSubscription);
					}
					// send 200ok late to allow deeper analysis of request
					belle_sip_server_transaction_send_response(server_transaction, resp.get());
					for (auto& listener : listSubscription->getListeners())
						listener->enableBypass(bypass); // expiration is handled by dialog

					mPresentityManager->addOrUpdateListeners(listSubscription->getListeners());
					listSubscription->notify(true);
				};
				if (!contentType) { // case of rfc4662 (list subscription without resource list in body)
#if ENABLE_SOCI
					if (!mThreadPool || !mConnPool) {
						LOGE << "Cannot answer a bodiless subscription: no available pool";
						goto error;
					}

					listSubscription = make_shared<ExternalListSubscription>(
					    expires, server_transaction, mProvider, mMaxPresenceInfoNotifiedAtATime,
					    mPresenceStats.countExternalListSub, listAvailableLambda, mRequest, mConnPool,
					    mThreadPool.get());
#else
					goto error;
#endif
				} else if ( // case of rfc5367 (list subscription with resource list in body)
				    content_disposition &&
				    (strcasecmp(belle_sip_header_content_disposition_get_content_disposition(content_disposition),
				                "recipient-list") == 0) &&
				    strcasecmp(belle_sip_header_content_type_get_type(contentType), "application") == 0 &&
				    strcasecmp(belle_sip_header_content_type_get_subtype(contentType), "resource-lists+xml") == 0) {
					listSubscription = make_shared<BodyListSubscription>(
					    expires, server_transaction, mProvider, mMaxPresenceInfoNotifiedAtATime,
					    mPresenceStats.countBodyListSub, listAvailableLambda);
				} else { // Unsuported
				error:
					LOGI << "Unsupported media type ["
					     << (contentType ? belle_sip_header_content_type_get_type(contentType) : "not set") << "/"
					     << (contentType ? belle_sip_header_content_type_get_subtype(contentType) : "not set") << "]";
					throw BelleSipSignalingException{
					    415, belle_sip_header_create("Accept", "application/resource-lists+xml")};
				}
				setSubscription(dialog.get(), listSubscription);
			} else { // Simple subscription
				auto sub = make_shared<PresenceSubscription>(expires, belle_sip_request_get_uri(request), dialog,
				                                             mProvider, mPresenceStats.countPresenceSub);
				shared_ptr<PresentityPresenceInformationListener> subscription{sub};
				setSubscription(dialog.get(), sub);
				LOGD << "Setting sub pointer [" << belle_sip_dialog_get_application_data(dialog.get())
				     << "] to dialog [" << dialog.get() << "]";
				// send 200ok late to allow deeper anylise of request
				belle_sip_server_transaction_send_response(server_transaction, resp.get());
				subscription->enableBypass(bypass);
				mPresentityManager->addOrUpdateListener(subscription, expires);
			}

			break;
		}
		case BELLE_SIP_DIALOG_CONFIRMED: {
			auto subscription = getSubscription(dialog.get());

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

			if (!subscription || subscription->getState() == Subscription::State::terminated) {
				LOGI << "Subscription [" << hex << subscription << "] for dialog [" << BELLE_SIP_OBJECT(dialog.get())
				     << "] already in terminated state";
				throw BelleSipSignalingException{481};
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

			belle_sip_response_t* resp = belle_sip_response_create_from_request(request, 200);
			belle_sip_server_transaction_send_response(server_transaction, resp);

			if (expires == 0) {
				removeSubscription(subscription);
			} else {
				// update expires
				subscription->increaseExpirationTime(expires);
				if (dynamic_pointer_cast<PresentityPresenceInformationListener>(subscription)) {
					auto listener = dynamic_pointer_cast<PresentityPresenceInformationListener>(subscription);
					mPresentityManager->addOrUpdateListener(listener, expires);
				} else {
					// list subscription case
					auto listSubscription = dynamic_pointer_cast<ListSubscription>(subscription);
					for (shared_ptr<PresentityPresenceInformationListener>& listener :
					     listSubscription->getListeners()) {
						listener->enableBypass(bypass); // expiration is handled by dialog
					}
					mPresentityManager->addOrUpdateListeners(listSubscription->getListeners(), expires);
				}
			}
			break;
		}

		default: {
			LOGI << "Unexpected request [" << hex << (long)request << "] for dialog [" << hex << (long)dialog.get()
			     << "in state [" << belle_sip_dialog_state_to_string(belle_sip_dialog_get_state(dialog.get()));
			throw BelleSipSignalingException{400};
		}
	}
}

void PresenceServer::removeSubscription(shared_ptr<Subscription>& subscription) {
	subscription->setState(Subscription::State::terminated);
	if (dynamic_pointer_cast<PresenceSubscription>(subscription)) {
		shared_ptr<PresentityPresenceInformationListener> listener =
		    dynamic_pointer_cast<PresentityPresenceInformationListener>(subscription);
		mPresentityManager->removeListener(listener);
	} else {
		// list subscription case
		shared_ptr<ListSubscription> listSubscription = dynamic_pointer_cast<ListSubscription>(subscription);
		for (shared_ptr<PresentityPresenceInformationListener> listener : listSubscription->getListeners()) {
			mPresentityManager->removeListener(listener);
		}
		listSubscription->notify(0); // to trigger final notify
	}
}

belle_sip_main_loop_t* PresenceServer::getBelleSipMainLoop() {
	return belle_sip_stack_get_main_loop(mStack);
}

void PresenceServer::enableLongTermPresence(const std::shared_ptr<AuthDb>& authDb,
                                            const std::shared_ptr<RegistrarDb>& registrarDb) {
	auto presenceLongTerm = std::make_shared<PresenceLongterm>(getBelleSipMainLoop(), authDb, registrarDb);
	mPresentityManager->addPresenceInfoObserver(presenceLongTerm);
}