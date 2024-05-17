/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <chrono>

#include <belle-sip/belle-sip.h>
#include <belle-sip/bodyhandler.h>
#include <belle-sip/mainloop.h>

#include <flexisip/logmanager.hh>

#include "bellesip-signaling-exception.hh"
#include "list-subscription.hh"
#include "presence/presentity/presentity-presence-information.hh"

using namespace std;

namespace flexisip {

ListSubscription::ListSubscription(unsigned int expires,
                                   belle_sip_server_transaction_t* ist,
                                   belle_sip_provider_t* aProv,
                                   size_t maxPresenceInfoNotifiedAtATime,
                                   const std::weak_ptr<StatPair>& countListSubscription,
                                   function<void(shared_ptr<ListSubscription>)> listAvailable)
    : Subscription("Presence",
                   expires,
                   belle_sip_transaction_get_dialog(BELLE_SIP_TRANSACTION(ist)),
                   aProv,
                   countListSubscription),
      mMaxPresenceInfoNotifiedAtATime(maxPresenceInfoNotifiedAtATime), mListAvailable(listAvailable) {
}

list<shared_ptr<PresentityPresenceInformationListener>>& ListSubscription::getListeners() {
	return mListeners;
}
ListSubscription::~ListSubscription() {
	if (mTimer) {
		belle_sip_source_cancel(mTimer.get());
	}
	SLOGD << "List subscription [" << this << "] deleted";
};

void ListSubscription::addInstanceToResource(Xsd::Rlmi::Resource& resource,
                                             list<belle_sip_body_handler_t*>& multipartList,
                                             PresentityPresenceInformation& presentityInformation,
                                             bool extended) {

	// we have a resource instance
	// subscription state is always active until we implement ACL
	Xsd::Rlmi::Instance instance("1", Xsd::Rlmi::State::active);
	char cid_rand_part[8];
	belle_sip_random_token(cid_rand_part, sizeof(cid_rand_part));
	ostringstream cid;
	cid << cid_rand_part << "@" << belle_sip_uri_get_host(mName.get());
	instance.setCid(cid.str());
	string pidf = presentityInformation.getPidf(extended);
	belle_sip_memory_body_handler_t* bodyPart =
	    belle_sip_memory_body_handler_new_copy_from_buffer((void*)pidf.c_str(), pidf.length(), nullptr, nullptr);
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
	SLOGI << "Presence info " << (extended ? "(extended)" : "(non-extended)") << " added to list [" << mName.get()
	      << " for entity [" << presentityInformation.getEntity() << "]";
}

void ListSubscription::notify(bool isFullState) {
	belle_sip_multipart_body_handler_t* multiPartBody;
	try {
		char* uri = belle_sip_uri_to_string(mName.get());
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
		if (mVersion == 0 && !isFullState) {
			/*
			 The
			 first NOTIFY sent in a subscription MUST contain full state, as must
			 the first NOTIFY sent after receipt of a SUBSCRIBE request for the
			 subscription.
			 */
			SLOGE << "First NOTIFY sent in subscription [" << mName.get() << "] MUST contain full state";
		}
		Xsd::Rlmi::List resourceList(string(uri), mVersion, isFullState);
		belle_sip_free(uri);
		list<belle_sip_body_handler_t*> multipartList;

		if (isFullState) {
			SLOGI << "Building full state rlmi for list name [" << mName.get() << "]";
			for (shared_ptr<PresentityPresenceInformationListener>& resourceListener : mListeners) {
				char* presentityUri = belle_sip_uri_to_string(resourceListener->getPresentityUri());
				Xsd::Rlmi::Resource resource(presentityUri);
				belle_sip_free(presentityUri);
				if (!resourceListener->getName().empty()) resource.getName().push_back(resourceListener->getName());

				PendingStateType::iterator it = mPendingStates.find(resourceListener->getPresentityUri());
				if (it != mPendingStates.end() && it->second.first->isKnown() &&
				    resourceList.getResource().size() < mMaxPresenceInfoNotifiedAtATime) {
					PresentityPresenceInformation& presentityInformation = *it->second.first;
					addInstanceToResource(resource, multipartList, presentityInformation,
					                      resourceListener->extendedNotifyEnabled());
					mPendingStates.erase(it); // might be optimized
				} else {
					SLOGI << "No presence info yet for uri [" << resourceListener->getPresentityUri() << "]";
				}
				resourceList.getResource().push_back(resource);
			}
		} else {
			SLOGI << "Building partial state rlmi for list name [" << mName.get() << "]";
			for (PendingStateType::iterator it = mPendingStates.begin();
			     it != mPendingStates.end() && resourceList.getResource().size() < mMaxPresenceInfoNotifiedAtATime;
			     /*nop*/) {
				pair<const belle_sip_uri_t*, pair<shared_ptr<PresentityPresenceInformation>, bool>>
				    presenceInformationPair = *it;
				if (presenceInformationPair.second.first->isKnown()) { /* only notify for entity with known state*/
					shared_ptr<PresentityPresenceInformation> presenceInformation =
					    presenceInformationPair.second.first;
					const belle_sip_uri_t* entity = presenceInformation->getEntity();
					char* presentityUri = belle_sip_uri_to_string(entity);
					Xsd::Rlmi::Resource resource(presentityUri);
					belle_sip_free(presentityUri);
					if (!presenceInformation->getName().empty())
						resource.getName().push_back(presenceInformation->getName());
					addInstanceToResource(resource, multipartList, *presenceInformation,
					                      presenceInformationPair.second.second);
					resourceList.getResource().push_back(resource);
				}
				it = mPendingStates.erase(it); // erase in any case
			}
		}

		// now building full body
		char cid_rand_part[8];
		belle_sip_random_token(cid_rand_part, sizeof(cid_rand_part));
		ostringstream cid;
		cid << (const char*)cid_rand_part << "@" << belle_sip_uri_get_host(mName.get());

		// Serialize the object model to XML.
		//
		Xsd::XmlSchema::NamespaceInfomap map;
		map[""].name = "urn:ietf:params:xml:ns:rlmi";
		stringstream out;
		Xsd::Rlmi::serializeList(out, resourceList, map);

		belle_sip_memory_body_handler_t* firstBodyPart = belle_sip_memory_body_handler_new_copy_from_buffer(
		    (void*)out.str().c_str(), out.str().length(), nullptr, nullptr);
		belle_sip_body_handler_add_header(BELLE_SIP_BODY_HANDLER(firstBodyPart),
		                                  belle_sip_header_create("Content-Transfer-Encoding", "binary"));
		ostringstream content_id;
		content_id << "<" << cid.str() << ">";
		belle_sip_body_handler_add_header(BELLE_SIP_BODY_HANDLER(firstBodyPart),
		                                  belle_sip_header_create("Content-Id", cid.str().c_str()));
		belle_sip_body_handler_add_header(
		    BELLE_SIP_BODY_HANDLER(firstBodyPart),
		    belle_sip_header_create("Content-Type", "application/rlmi+xml;charset=\"UTF-8\""));
		multiPartBody =
		    belle_sip_multipart_body_handler_new(nullptr, nullptr, BELLE_SIP_BODY_HANDLER(firstBodyPart), nullptr);
		for (belle_sip_body_handler_t* additionalPart : multipartList) {
			belle_sip_multipart_body_handler_add_part(multiPartBody, additionalPart);
		}

		Subscription::notify(multiPartBody, "deflate");
		mVersion++;
		mLastNotify = chrono::system_clock::now();
		if (!mPendingStates.empty() && !mTimer) {
			SLOGD << "Still [" << mPendingStates.size() << "] to be notified for list [" << this << "]";
			auto func = [this]([[maybe_unused]] unsigned int events) {
				mTimer.reset(nullptr);
				notify(false);
				SLOGD << "defered notify sent on [" << this << "]";
				return BELLE_SIP_STOP;
			};
			mTimer = belle_sip_main_loop_create_cpp_timeout(
			    belle_sip_stack_get_main_loop(belle_sip_provider_get_sip_stack(mProv)), func, 500,
			    "timer for list notify");
		}
	} catch (const Xsd::XmlSchema::Serialization& e) {
		throw FLEXISIP_EXCEPTION << "serialization error: " << e.diagnostics();
	} catch (exception& e) {
		throw FLEXISIP_EXCEPTION << "Cannot get build list notidy for [" << mName.get() << "]error [" << e.what()
		                         << "]";
	}
}
void ListSubscription::onInformationChanged(PresentityPresenceInformation& presenceInformation, bool extended) {
	// store state, erase previous one if any
	if (getState() == State::active) {
		mPendingStates[presenceInformation.getEntity()] = make_pair(presenceInformation.shared_from_this(), extended);

		if (isTimeToNotify()) {
			notify(false);
		} else {
			if (mVersion > 0 /*special case for first notify */ && mTimer == nullptr) {
				// cb function to invalidate an unrefreshed etag;
				auto func = [this]([[maybe_unused]] unsigned int events) {
					notify(false);
					SLOGD << "defered notify sent on [" << this << "]";
					mTimer.reset(nullptr);
					return BELLE_SIP_STOP;
				};
				// create timer
				chrono::milliseconds timeout{chrono::duration_cast<chrono::milliseconds>(
				    mMinNotifyInterval - (chrono::system_clock::now() - mLastNotify))};

				mTimer = belle_sip_main_loop_create_cpp_timeout(
				    belle_sip_stack_get_main_loop(belle_sip_provider_get_sip_stack(mProv)), func, timeout.count(),
				    "timer for list notify");
			}

			if (mVersion > 0) {
				SLOGI << "Defering presence information notify for entity [" << presenceInformation.getEntity() << "/"
				      << this << "] to [" << (belle_sip_source_get_timeout_int64(mTimer.get())) << " ms]";
			} else {
				SLOGI << "First notify, defering presence information for entity [" << presenceInformation.getEntity()
				      << "/" << this << "]";
			}
		}
	} // else for list subscription final notify is handled separatly
}

bool ListSubscription::isTimeToNotify() {
	return mVersion == 0 ? false : (chrono::system_clock::now() - mLastNotify) > mMinNotifyInterval;
}

void ListSubscription::finishCreation(belle_sip_server_transaction_t* ist) {
	auto func = [this, ist]() {
		if (mListeners.empty()) {
			auto dialog = mDialog.lock();
			auto callid =
			    dialog ? belle_sip_header_call_id_get_call_id(belle_sip_dialog_get_call_id(dialog.get())) : "nullptr";
			SLOGD << "Empty list entry for dialog id[" << callid << "]";
			setState(Subscription::State::terminated);
		}

		belle_sip_request_t* request = belle_sip_transaction_get_request(BELLE_SIP_TRANSACTION(ist));
		mName = bellesip::shared_ptr<const belle_sip_uri_t>{reinterpret_cast<belle_sip_uri_t*>(
		    belle_sip_object_clone(BELLE_SIP_OBJECT(belle_sip_request_get_uri(request))))};
		mListAvailable(static_pointer_cast<ListSubscription>(shared_from_this()));
	};
	belle_sip_main_loop_cpp_do_later(belle_sip_stack_get_main_loop(belle_sip_provider_get_sip_stack(mProv)), func,
	                                 "deferred task for external list subscription");
}

/// PresentityResourceListener//

PresentityResourceListener::PresentityResourceListener(ListSubscription& aListSubscription,
                                                       const belle_sip_uri_t* presentity,
                                                       const string& name)
    : mListSubscription(aListSubscription),
      mPresentity((belle_sip_uri_t*)belle_sip_object_clone(BELLE_SIP_OBJECT(presentity))), mName(name) {
	belle_sip_object_ref(mPresentity);
}
PresentityResourceListener::~PresentityResourceListener() {
	belle_sip_object_unref(mPresentity);
}
PresentityResourceListener::PresentityResourceListener(const PresentityResourceListener& source)
    : mListSubscription(source.mListSubscription), mName(source.mName) {
	mPresentity = ((belle_sip_uri_t*)belle_sip_object_clone(BELLE_SIP_OBJECT(source.getPresentityUri())));
	belle_sip_object_ref(mPresentity);
}
const belle_sip_uri_t* PresentityResourceListener::getPresentityUri() const {
	return mPresentity;
}
/*
 * This function is call every time Presentity information need to be notified to a UA
 */
void PresentityResourceListener::onInformationChanged(PresentityPresenceInformation& presenceInformation,
                                                      bool extended) {
	// Notification is handled globaly for the list
	if (!mName.empty()) presenceInformation.setName(mName);
	mListSubscription.onInformationChanged(presenceInformation, extended);
}
void PresentityResourceListener::onExpired([[maybe_unused]] PresentityPresenceInformation& presenceInformation) {
	// fixme check if enought
	mListSubscription.setState(Subscription::State::terminated);
}
const belle_sip_uri_t* PresentityResourceListener::getFrom() {
	return mListSubscription.getFrom();
}
const belle_sip_uri_t* PresentityResourceListener::getTo() {
	return mListSubscription.getTo();
}

} // namespace flexisip
