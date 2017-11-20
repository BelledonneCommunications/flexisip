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

#include "list-subscription.hh"
#include "belle-sip/belle-sip.h"
#include "bellesip-signaling-exception.hh"
#include "log/logmanager.hh"
#include "resource-lists.hxx"
#include <chrono>
#include "rlmi+xml.hxx"
#include "belle-sip/bodyhandler.h"
#include <algorithm>

using namespace std;

namespace flexisip {

ListSubscription::ListSubscription(unsigned int expires, belle_sip_server_transaction_t *ist,
								   belle_sip_provider_t *aProv)
	: Subscription("Presence", expires, belle_sip_transaction_get_dialog(BELLE_SIP_TRANSACTION(ist)), aProv),
	  mLastNotify(chrono::system_clock::time_point::min()), mMinNotifyInterval(2 /*60*/), mVersion(0), mTimer(NULL) {
	belle_sip_request_t *request = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(ist));
	belle_sip_header_content_type_t *contentType =
		belle_sip_message_get_header_by_type(request, belle_sip_header_content_type_t);
	// check content type
	if (!contentType || strcasecmp(belle_sip_header_content_type_get_type(contentType), "application") != 0 ||
		strcasecmp(belle_sip_header_content_type_get_subtype(contentType), "resource-lists+xml") != 0) {

		throw BELLESIP_SIGNALING_EXCEPTION_1(415, belle_sip_header_create("Accept", "application/resource-lists+xml"))
			<< "Unsupported media type ["
			<< (contentType ? belle_sip_header_content_type_get_type(contentType) : "not set") << "/"
			<< (contentType ? belle_sip_header_content_type_get_subtype(contentType) : "not set") << "]";
	}
	if (!belle_sip_message_get_body(BELLE_SIP_MESSAGE(request))) {
		throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", "Empty body")) << "Empty body";
	}
	::std::unique_ptr<resource_lists::Resource_lists> resource_list_body = NULL;
	try {
		istringstream data(belle_sip_message_get_body(BELLE_SIP_MESSAGE(request)));
		resource_list_body = resource_lists::parseResource_lists(data, xml_schema::Flags::dont_validate);
	} catch (const xml_schema::Exception &e) {
		ostringstream os;
		os << "Cannot parse body caused by [" << e << "]";
		// todo check error code
		throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", os.str().c_str())) << os.str();
	}

	for (::resource_lists::List::ListConstIterator listIt = resource_list_body->getList().begin();
		 listIt != resource_list_body->getList().end(); listIt++) {
		for (::resource_lists::List::EntryConstIterator entryIt = listIt->getEntry().begin();
			 entryIt != listIt->getEntry().end(); entryIt++) {
			//fixme until we have a fast uri parser
			//belle_sip_uri_t *uri = belle_sip_uri_parse(entryIt->getUri().c_str());
			int username_begin = entryIt->getUri().find(':')+1;
			int username_end = entryIt->getUri().find('@');
			int domain_end = entryIt->getUri().find(';');
			string username = entryIt->getUri().substr(username_begin,username_end-username_begin);
			string domain = entryIt->getUri().substr(username_end+1,domain_end - (username_end+1));
			belle_sip_uri_t *uri = belle_sip_uri_create(username.c_str(), domain.c_str());
			if (!uri || !belle_sip_uri_get_host(uri) || !belle_sip_uri_get_user(uri)) {
				ostringstream os;
				os << "Cannot parse list entry [" << entryIt->getUri() << "]";
				throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", os.str().c_str())) << os.str();
			}
			if (entryIt->getUri().find(";user=phone") != string::npos) {
				belle_sip_uri_set_user_param(uri,"phone");
			}
			mListeners.push_back(make_shared<PresentityResourceListener>(*this, uri));
			belle_sip_object_unref(uri);
		}
	}
	if (mListeners.size() == 0) {
		ostringstream os;
		os << "Empty list entry for dialog id[" << belle_sip_header_call_id_get_call_id(belle_sip_dialog_get_call_id(mDialog)) << "]";
		throw BELLESIP_SIGNALING_EXCEPTION_1(400, belle_sip_header_create("Warning", os.str().c_str())) << os.str();
	}

	mName = (belle_sip_uri_t *)belle_sip_object_clone(BELLE_SIP_OBJECT(belle_sip_request_get_uri(request)));
	belle_sip_object_ref((void *)mName);
}

list<shared_ptr<PresentityPresenceInformationListener>> &ListSubscription::getListeners() {
	return mListeners;
}
ListSubscription::~ListSubscription() {
	if (mTimer) {
		belle_sip_source_cancel(mTimer);
		belle_sip_object_unref(mTimer);
	}
	belle_sip_object_unref((void *)mName);
	SLOGD << "List souscription ["<< this <<"] deleted";
};

void ListSubscription::addInstanceToResource(rlmi::Resource &resource, list<belle_sip_body_handler_t *> &multipartList,
											 PresentityPresenceInformation &presentityInformation, bool extended) {

	// we have a resource instance
	// subscription state is always active until we implement ACL
	rlmi::Instance instance("1", rlmi::State::active);
	char cid_rand_part[8];
	belle_sip_random_token(cid_rand_part, sizeof(cid_rand_part));
	ostringstream cid;
	cid << (const char *)cid_rand_part << "@" << belle_sip_uri_get_host(mName);
	instance.setCid(cid.str());
	string pidf = presentityInformation.getPidf(extended);
	belle_sip_memory_body_handler_t *bodyPart =
		belle_sip_memory_body_handler_new_copy_from_buffer((void *)pidf.c_str(), pidf.length(), NULL, NULL);
	belle_sip_body_handler_add_header(BELLE_SIP_BODY_HANDLER(bodyPart),
									  belle_sip_header_create("Content-Transfer-Encoding", "binary"));
	ostringstream content_id;
	content_id << "<" << cid.str() << ">";
	belle_sip_body_handler_add_header(BELLE_SIP_BODY_HANDLER(bodyPart),
									  belle_sip_header_create("Content-Id", cid.str().c_str()));
	belle_sip_body_handler_add_header(
		BELLE_SIP_BODY_HANDLER(bodyPart),
		belle_sip_header_create("Content-Type", "application/pidf+xml;charset=\"UTF-8\""));
	multipartList.push_back(BELLE_SIP_BODY_HANDLER(bodyPart));
	resource.getInstance().push_back(instance);
	SLOGI << "Presence info added to list [" << mName << " for entity [" << presentityInformation.getEntity() << "]";
}

void ListSubscription::notify(bool isFullState) {
	belle_sip_multipart_body_handler_t *multiPartBody;
	try {
		char *uri = belle_sip_uri_to_string(mName);
		/* 5.2
		 * The third mandatory attribute is "fullState".  The "fullState"
		 * attribute indicates whether the NOTIFY message contains information
		 * for every resource in the list.  If it does, the value of the
		 * attribute is "true" (or "1"); otherwise, it is "false" (or "0").  The
		 * first NOTIFY sent in a subscription MUST contain full state, as must
		 * the first NOTIFY sent after receipt of a SUBSCRIBE request for the
		 * subscription.
		 *
		 */
		if (mVersion == 0 && isFullState == false) {
			/*
			 The
			 first NOTIFY sent in a subscription MUST contain full state, as must
			 the first NOTIFY sent after receipt of a SUBSCRIBE request for the
			 subscription.
			 */
			SLOGE << "First NOTIFY sent in subscription [" << mName << "] MUST contain full state";
		}
		rlmi::List resourceList(string(uri), mVersion, isFullState);
		belle_sip_free(uri);
		list<belle_sip_body_handler_t *> multipartList;

		if (isFullState) {
			SLOGI << "Building full state rlmi for list name [" << mName << "]";
			for (shared_ptr<PresentityPresenceInformationListener> &resourceListener : mListeners) {
				char *presentityUri = belle_sip_uri_to_string(resourceListener->getPresentityUri());
				rlmi::Resource resource(presentityUri);
				belle_sip_free(presentityUri);
				PendingStateType::iterator it = mPendingStates.find(resourceListener->getPresentityUri());
				if (it != mPendingStates.end() && it->second.first->isKnown()) {
					addInstanceToResource(resource, multipartList, *it->second.first, resourceListener->extendedNotifyEnabled());
				} else {
					SLOGI << "No presence info yet for uri [" << resourceListener->getPresentityUri() << "]";
				}
				resourceList.getResource().push_back(resource);
			}

		} else {
			SLOGI << "Building partial state rlmi for list name [" << mName << "]";
			for (pair<const belle_sip_uri_t *, pair<shared_ptr<PresentityPresenceInformation>,bool>> presenceInformationPair :
				 mPendingStates) {
				if (presenceInformationPair.second.first->isKnown()) { /* only notify for entity with known state*/
					shared_ptr<PresentityPresenceInformation> presenceInformation = presenceInformationPair.second.first;
					char *presentityUri = belle_sip_uri_to_string(presenceInformation->getEntity());
					rlmi::Resource resource(presentityUri);
					belle_sip_free(presentityUri);
					addInstanceToResource(resource, multipartList, *presenceInformation, presenceInformationPair.second.second);
					resourceList.getResource().push_back(resource);
				}
			}
		}

		// now building full body
		char cid_rand_part[8];
		belle_sip_random_token(cid_rand_part, sizeof(cid_rand_part));
		ostringstream cid;
		cid << (const char *)cid_rand_part << "@" << belle_sip_uri_get_host(mName);

		// Serialize the object model to XML.
		//
		xml_schema::NamespaceInfomap map;
		map[""].name = "urn:ietf:params:xml:ns:rlmi";
		stringstream out;
		rlmi::serializeList(out, resourceList, map);

		belle_sip_memory_body_handler_t *firstBodyPart = belle_sip_memory_body_handler_new_copy_from_buffer(
			(void *)out.str().c_str(), out.str().length(), NULL, NULL);
		belle_sip_body_handler_add_header(BELLE_SIP_BODY_HANDLER(firstBodyPart),
										  belle_sip_header_create("Content-Transfer-Encoding", "binary"));
		ostringstream content_id;
		content_id << "<" << cid.str() << ">";
		belle_sip_body_handler_add_header(BELLE_SIP_BODY_HANDLER(firstBodyPart),
										  belle_sip_header_create("Content-Id", cid.str().c_str()));
		belle_sip_body_handler_add_header(
			BELLE_SIP_BODY_HANDLER(firstBodyPart),
			belle_sip_header_create("Content-Type", "application/rlmi+xml;charset=\"UTF-8\""));
		multiPartBody = belle_sip_multipart_body_handler_new(NULL, NULL, BELLE_SIP_BODY_HANDLER(firstBodyPart), NULL);
		for (belle_sip_body_handler_t *additionalPart : multipartList) {
			belle_sip_multipart_body_handler_add_part(multiPartBody, additionalPart);
		}

		Subscription::notify(multiPartBody, "deflate");
		mVersion++;
		mLastNotify = chrono::system_clock::now();
		mPendingStates.clear();
	} catch (const xml_schema::Serialization &e) {
		throw FLEXISIP_EXCEPTION << "serialization error: " << e.diagnostics();
	} catch (exception &e) {
		throw FLEXISIP_EXCEPTION << "Cannot get build list notidy for [" << mName << "]error [" << e.what() << "]";
	}
}
void ListSubscription::onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extended) {
	// store state, erase previous one if any
	if (getState() == active) {
		mPendingStates[presenceInformation.getEntity()] = std::make_pair(presenceInformation.shared_from_this(), extended);

		if (isTimeToNotify()) {
			notify(FALSE);
		} else {
			if (mVersion > 0 /*special case for first notify */ && mTimer == NULL) {
				// cb function to invalidate an unrefreshed etag;
				belle_sip_source_cpp_func_t *func = new belle_sip_source_cpp_func_t([this](unsigned int events) {
					this->notify(FALSE);
					SLOGD << "defered notify sent on [" << this << "]";
					belle_sip_object_unref(this->mTimer);
					this->mTimer = NULL;
					return BELLE_SIP_STOP;
				});
				// create timer
				chrono::milliseconds timeout(chrono::duration_cast<chrono::milliseconds>(
					mMinNotifyInterval - (chrono::system_clock::now() - mLastNotify)));

				mTimer = belle_sip_main_loop_create_cpp_timeout( belle_sip_stack_get_main_loop(belle_sip_provider_get_sip_stack(mProv))
																	, func
																	, timeout.count()
																	, "timer for list notify");
			}

			if (mVersion > 0) {
				SLOGI << "Defering presence information notify for entity [" << presenceInformation.getEntity()
					  << "/"<<this<<"] to [" << (belle_sip_source_get_timeout(mTimer)) << " ms]";
			} else {
				SLOGI << "First notify, defering presence information for entity [" << presenceInformation.getEntity()
					   << "/"<<this<<"]";
				
				
			}
		}
	} // else for list subscription final notify is handled separatly
}

bool ListSubscription::isTimeToNotify() {
	if (mVersion == 0) {
		return FALSE; // initial notify not sent yet
	}
	return (chrono::system_clock::now() - mLastNotify) > mMinNotifyInterval;
}

/// PresentityResourceListener//

PresentityResourceListener::PresentityResourceListener(ListSubscription &aListSubscription,
													   const belle_sip_uri_t *presentity)
	: mListSubscription(aListSubscription),
	  mPresentity((belle_sip_uri_t *)belle_sip_object_clone(BELLE_SIP_OBJECT(presentity))) {
	belle_sip_object_ref(mPresentity);
}
PresentityResourceListener::~PresentityResourceListener() {
	belle_sip_object_unref(mPresentity);
}
PresentityResourceListener::PresentityResourceListener(const PresentityResourceListener &source)
	: mListSubscription(source.mListSubscription) {
	mPresentity = ((belle_sip_uri_t *)belle_sip_object_clone(BELLE_SIP_OBJECT(source.getPresentityUri())));
	belle_sip_object_ref(mPresentity);
}
const belle_sip_uri_t *PresentityResourceListener::getPresentityUri(void) const {
	return mPresentity;
}
/*
 * This function is call every time Presentity information need to be notified to a UA
 */
void PresentityResourceListener::onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extended) {
	// Notification is handled globaly for the list
	mListSubscription.onInformationChanged(presenceInformation, extended);
}
void PresentityResourceListener::onExpired(PresentityPresenceInformation &presenceInformation) {
	// fixme check if enought
	mListSubscription.setState(Subscription::State::terminated);
}
const belle_sip_uri_t* PresentityResourceListener::getFrom() {
	return mListSubscription.getFrom();
}
const belle_sip_uri_t* PresentityResourceListener::getTo() {
	return mListSubscription.getTo();
}
}
