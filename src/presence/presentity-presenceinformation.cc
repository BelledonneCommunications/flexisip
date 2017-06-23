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
#include "presentity-presenceinformation.hh"
#include "belle-sip/belle-sip.h"
#include "utils/flexisip-exception.hh"
#include <ostream>
#include <functional>
#include "etag-manager.hh"
#include "pidf+xml.hxx"
#include "rpid.hxx"
#include "data-model.hxx"
#include <memory>
#include "presentity-manager.hh"
#include "log/logmanager.hh"

#define ETAG_SIZE 8
using namespace pidf;
using namespace rpid;
using namespace data_model;
using namespace std;

namespace flexisip {

static string generate_presence_id(void);

FlexisipException &operator<<(FlexisipException &e, const xml_schema::Exception &val) {
	stringstream e_out;
	e_out << val;
	e << e_out.str();
	return e;
}

PresenceInformationElement::PresenceInformationElement(const belle_sip_uri_t *contact)
	: mDomDocument(::xsd::cxx::xml::dom::create_document<char>()), mBelleSipMainloop(NULL), mTimer(NULL) {
	char *contact_as_string = belle_sip_uri_to_string(contact);
	std::time_t t;
	std::time(&t);
	struct tm *now = gmtime(&t);
	Status status;
	status.setBasic(Basic("open"));
	unique_ptr<Tuple> tup(new Tuple(status, string(generate_presence_id())));
	tup->setTimestamp(::xml_schema::DateTime(now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour,
											 now->tm_min, now->tm_sec));
	tup->setContact(::pidf::Contact(contact_as_string));
	mTuples.push_back(std::unique_ptr<Tuple>(tup.release()));
	Activities act = Activities();
	act.getAway().push_back(rpid::Empty());
	mPerson.setId(contact_as_string);
	mPerson.getActivities().push_back(act);
	belle_sip_free(contact_as_string);
}

PresentityPresenceInformation::PresentityPresenceInformation(const belle_sip_uri_t *entity, PresentityManager &presentityManager,
															 belle_sip_main_loop_t *mainloop)
	: mEntity((belle_sip_uri_t *)belle_sip_object_clone(BELLE_SIP_OBJECT(entity))), mPresentityManager(presentityManager),
	  mBelleSipMainloop(mainloop), mDefaultInformationElement(nullptr) {
	belle_sip_object_ref(mainloop);
	belle_sip_object_ref((void *)mEntity);
}

PresenceInformationElement::~PresenceInformationElement() {
	if (mBelleSipMainloop)
		setExpiresTimer(NULL);

	SLOGD << "Presence information element [" << std::hex << (long)this << "] deleted";
}

PresentityPresenceInformation::~PresentityPresenceInformation() {
	for (auto it = mInformationElements.begin(); it != mInformationElements.end(); it++) {
		delete it->second;
	}
	mInformationElements.clear();
	belle_sip_object_unref((void *)mEntity);
	belle_sip_object_unref((void *)mBelleSipMainloop);
	SLOGD << "Presence information [" << this << "] deleted";
}
size_t PresentityPresenceInformation::getNumberOfListeners() const {
	return mSubscribers.size();
}
std::list<shared_ptr<PresentityPresenceInformationListener>> PresentityPresenceInformation::getListeners() const {
	return mSubscribers;
}
size_t PresentityPresenceInformation::getNumberOfInformationElements() const {
	return mInformationElements.size();
}
bool PresentityPresenceInformation::findPresenceInfo(std::shared_ptr<PresentityPresenceInformation> &info) {
	for (shared_ptr<PresentityPresenceInformationListener> listener : mSubscribers) {
		if(belle_sip_uri_equals(listener->getTo(), info->getEntity())) {
			return true;
		}
	}
	return false;
}
string PresentityPresenceInformation::putTuples(pidf::Presence::TupleSequence &tuples,
												data_model::Person &person, int expires) {
	return setOrUpdate(&tuples, &person, NULL, expires);
}
string PresentityPresenceInformation::updateTuples(pidf::Presence::TupleSequence &tuples,
												   data_model::Person  &person, string &eTag,
												   int expires) throw(FlexisipException) {
	return setOrUpdate(&tuples, &person, &eTag, expires);
}
void PresenceInformationElement::clearTuples() {
	mTuples.clear();
}
string PresentityPresenceInformation::setOrUpdate(pidf::Presence::TupleSequence *tuples,
												  data_model::Person  *person, const string *eTag,
												  int expires) throw(FlexisipException) {
	PresenceInformationElement *informationElement = NULL;

	// etag ?
	if (eTag && eTag->size() > 0) {
		// check if already exist
		auto it = mInformationElements.find(*eTag);
		if (it == mInformationElements.end())
			throw FLEXISIP_EXCEPTION << "Unknown eTag [" << *eTag << "] for presentity [" << *this << "]";
		if (tuples == NULL) {
			// juste a refresh
			informationElement = it->second;
			SLOGD << "Updating presence information element [" << informationElement << "]  for presentity [" << *this
				  << "]";
		} else {
			// remove
			delete it->second;
			mInformationElements.erase(it);
		}

	} else {
		// no etag, check for tuples
		if (tuples == NULL)
			throw FLEXISIP_EXCEPTION << "Cannot create information element for presentity [" << *this
									 << "]  without tuple";
	}

	if (!informationElement) { // create a new one if needed
		informationElement = new PresenceInformationElement(tuples, person, mBelleSipMainloop);
		SLOGD << "Creating presence information element [" << informationElement << "]  for presentity [" << *this
			  << "]";
	}
	// generate new etag
	char generatedETag_char[ETAG_SIZE];
	belle_sip_random_token(generatedETag_char, sizeof(generatedETag_char));
	string generatedETag = generatedETag_char;

	// update etag for this information element
	informationElement->setEtag(generatedETag);

	// cb function to invalidate an unrefreshed etag;
	belle_sip_source_cpp_func_t *func =
		new belle_sip_source_cpp_func_t([this, generatedETag](unsigned int events) {
			// find information element
			this->removeTuplesForEtag(generatedETag);
			mPresentityManager.invalidateETag(generatedETag);
			SLOGD << "eTag [" << generatedETag << "] has expired";
			return BELLE_SIP_STOP;
		});
	// create timer
	belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(  mBelleSipMainloop
																	   , func
																	   , expires * 1000
																	   , "timer for presence Info");

	// set expiration timer
	informationElement->setExpiresTimer(timer);

	// modify global etag list
	if (eTag && eTag->size() > 0) {
		mPresentityManager.modifyEtag(*eTag, generatedETag);
		mInformationElements.erase(*eTag);
	} else {
		mPresentityManager.addEtag(shared_from_this(), generatedETag);
	}

	// modify etag list for this presenceInfo
	mInformationElements[generatedETag] = informationElement;

	// triger notify on all listeners
	notifyAll();
	SLOGD << "Etag [" << generatedETag << "] associated to Presentity [" << *this << "]";
	return generatedETag;
}

string PresentityPresenceInformation::refreshTuplesForEtag(const string &eTag, int expires) throw(FlexisipException) {
	return setOrUpdate(NULL, NULL, &eTag, expires);
}

void PresentityPresenceInformation::setDefaultElement(const char *contact) {
	mDefaultInformationElement = make_shared<PresenceInformationElement>(getEntity());

	if (contact) {
		for (auto & tup : mDefaultInformationElement->getTuples()) {
			tup->setContact(::pidf::Contact(contact));
		}
	}

	notifyAll();
}

void PresentityPresenceInformation::removeTuplesForEtag(const string &eTag) {
	auto it = mInformationElements.find(eTag);
	if (it != mInformationElements.end()) {
		PresenceInformationElement *informationElement = it->second;
		mInformationElements.erase(it);
		delete informationElement;
		notifyAll(); // Removing an event state change global state, so it should be notified
	} else
		SLOGD << "No tuples found for etag [" << eTag << "]";
}

FlexisipException &operator<<(FlexisipException &ex, const PresentityPresenceInformation &p) {
	return ex << "entity [" << p.getEntity() << "]/" << &p;
}
std::ostream &operator<<(std::ostream &__os, const PresentityPresenceInformation &p) {
	return __os << "entity [" << p.getEntity() << "]/" << &p;
}

const belle_sip_uri_t *PresentityPresenceInformation::getEntity() const {
	return mEntity;
}

void PresentityPresenceInformation::addOrUpdateListener(const shared_ptr<PresentityPresenceInformationListener> &listener) {
	addOrUpdateListener(listener, -1);
}

void PresentityPresenceInformation::addListenerIfNecessary(const shared_ptr<PresentityPresenceInformationListener> &listener) {
	// search if exist
	string op;
	bool listener_exist = false;
	for (const shared_ptr<PresentityPresenceInformationListener> &existing_listener : mSubscribers) {
		if (listener == existing_listener) {
			listener_exist = true;
			break;
		}
	}
	if (listener_exist) {
		op = "Updating";
	} else {
		// not found, adding
		mSubscribers.push_back(listener);
		op = "Adding";
	}
}

void PresentityPresenceInformation::addOrUpdateListener(const shared_ptr<PresentityPresenceInformationListener> &listener,
														int expires) {

	// search if exist
	string op;
	bool listener_exist = false;
	for (const shared_ptr<PresentityPresenceInformationListener> &existing_listener : mSubscribers) {
		if (listener == existing_listener) {
			listener_exist = true;
			break;
		}
	}
	if (listener_exist) {
		op = "Updating";
	} else {
		// not found, adding
		mSubscribers.push_back(listener);
		op = "Adding";
	}

	SLOGD << op << " listener [" << listener.get() << "] on [" << *this << "] for [" << expires << "] seconds";

	if (expires > 0) {
		// PresentityPresenceInformationListener* listener_ptr=listener.get();
		// cb function to invalidate an unrefreshed etag;
		belle_sip_source_cpp_func_t *func =
		new belle_sip_source_cpp_func_t([this, listener/*_ptr*/](unsigned int events) {
			SLOGD << "Listener [" << listener.get() << "] on [" << *this << "] has expired";
			listener->onExpired(*this);
			this->mPresentityManager.removeListener(listener);
			return BELLE_SIP_STOP;
		});
		// create timer
		belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(mBelleSipMainloop
																		   , func
																		   , expires * 1000, "timer for presence info listener");

		// set expiration timer
		listener->setExpiresTimer(mBelleSipMainloop, timer);
	} else {
		listener->setExpiresTimer(mBelleSipMainloop,NULL);
	}
	/*
	 *rfc 3265
	 * 3.1.6.2. Confirmation of Subscription Creation/Refreshing
	 *
	 * Upon successfully accepting or refreshing a subscription, notifiers
	 * MUST send a NOTIFY message immediately to communicate the current
	 * resource state to the subscriber.
	 */
	listener->onInformationChanged(*this, listener->extendedNotifyEnabled());
}
	
void PresentityPresenceInformation::removeListener(const shared_ptr<PresentityPresenceInformationListener> &listener) {
	SLOGD << "removing listener [" << listener.get() << "] on [" << *this << "]";
	// 1 cancel expiration time
	listener->setExpiresTimer(mBelleSipMainloop, NULL);
	// 2 remove listener
	mSubscribers.remove(listener);
	//			 3.1.4.3. Unsubscribing
	//
	//			 Unsubscribing is handled in the same way as refreshing of a
	//			 subscription, with the "Expires" header set to "0".  Note that a
	//			 successful unsubscription will also trigger a final NOTIFY message.
	listener->onInformationChanged(*this, listener->extendedNotifyEnabled());
}
	
bool PresentityPresenceInformation::hasDefaultElement() {
	return mDefaultInformationElement != nullptr;
}
bool PresentityPresenceInformation::isKnown() {
	return mInformationElements.size() > 0 || hasDefaultElement();
}
string PresentityPresenceInformation::getPidf(bool extended) throw(FlexisipException) {
	stringstream out;
	try {
		char *entity = belle_sip_uri_to_string(getEntity());
		pidf::Presence presence((string(entity)));
		belle_sip_free(entity);
		list<string> tupleList;

		if(extended) {
			for (auto element : mInformationElements) {
				// copy pidf
				for (const unique_ptr<pidf::Tuple> &tup : element.second->getTuples()) {
					// check for multiple tupple id, may happend with buggy presence publisher
					if (find(tupleList.begin(), tupleList.end(), tup.get()->getId()) == tupleList.end()) {
						presence.getTuple().push_back(*tup);
						tupleList.push_back(tup.get()->getId());
					} else {
						SLOGW << "Already existing tuple id [" << tup.get()->getId() << " for [" << *this << "], skipping";
					}
				}
				// copy extensions
				Person dm_person = element.second->getPerson();
				for(data_model::Person::ActivitiesIterator activity = dm_person.getActivities().begin(); activity != dm_person.getActivities().end();activity++) {
					if(!presence.getPerson()) {
						Person person = Person(dm_person.getId());
						presence.setPerson(person);
					}
					presence.getPerson()->getActivities().push_back(*activity);
				}
			}
		}
		if ((mInformationElements.size() == 0 || !extended) && mDefaultInformationElement != nullptr) {
			// insering default tuple
			presence.getTuple().push_back(*mDefaultInformationElement->getTuples().begin()->get());

			// copy extensions
			Person dm_person = mDefaultInformationElement->getPerson();
			for(data_model::Person::ActivitiesIterator activity = dm_person.getActivities().begin(); activity != dm_person.getActivities().end();activity++) {
				if(!presence.getPerson()) {
					Person person = Person(dm_person.getId());
					presence.setPerson(person);
				}
				presence.getPerson()->getActivities().push_back(*activity);
			}
		}
		if (presence.getTuple().size() == 0) {
			pidf::Note value;
			namespace_::Lang lang("en");
			value += "No presence information available yet";
			value.setLang(lang);
			// value.lang("en");
			presence.getNote().push_back(value);
		}

		// Serialize the object model to XML.
		//
		xml_schema::NamespaceInfomap map;
		map[""].name = "urn:ietf:params:xml:ns:pidf";

		serializePresence(out, presence, map);

	} catch (const xml_schema::Exception &e) {
		throw FLEXISIP_EXCEPTION << "error: " << e;
	} catch (exception &e) {
		throw FLEXISIP_EXCEPTION << "Cannot get pidf for for [" << *this << "]error [" << e.what() << "]";
	}

	return out.str();
}

void PresentityPresenceInformation::notifyAll() {
	for (shared_ptr<PresentityPresenceInformationListener> listener : mSubscribers) {
		listener->onInformationChanged(*this, listener->extendedNotifyEnabled());
	}
	SLOGD << *this << " has notified [" << mSubscribers.size() << " ] listeners";
}
PresentityPresenceInformationListener::PresentityPresenceInformationListener() : mTimer(NULL), mExtendedNotify(false), mBypassEnabled(false) {
}
PresentityPresenceInformationListener::~PresentityPresenceInformationListener() {
	setExpiresTimer(mBelleSipMainloop, NULL);
}
bool PresentityPresenceInformationListener::extendedNotifyEnabled() {
	return mExtendedNotify;
}
void PresentityPresenceInformationListener::enableExtendedNotify(bool enable) {
	mExtendedNotify = this->bypassEnabled() || enable;
}
bool PresentityPresenceInformationListener::bypassEnabled() {
	return mBypassEnabled;
}
void PresentityPresenceInformationListener::enableBypass(bool enable) {
	mBypassEnabled = enable;
}
void PresentityPresenceInformationListener::setExpiresTimer(belle_sip_main_loop_t *ml, belle_sip_source_t *timer) {
	if (mTimer) {
		// canceling previous timer
		belle_sip_source_cancel(mTimer);
		belle_sip_object_unref(mTimer);
	}
	mBelleSipMainloop=ml;
	mTimer = timer;
}

// PresenceInformationElement

PresenceInformationElement::PresenceInformationElement(pidf::Presence::TupleSequence *tuples,
													   data_model::Person *person,
													   belle_sip_main_loop_t *mainLoop)
	: mDomDocument(::xsd::cxx::xml::dom::create_document<char>()), mBelleSipMainloop(mainLoop), mTimer(NULL) {

	for (pidf::Presence::TupleSequence::iterator tupleIt = tuples->begin(); tupleIt != tuples->end();) {
		SLOGD << "Adding tuple id [" << tupleIt->getId() << "] to presence info element [" << this << "]";
		std::unique_ptr<Tuple> r;
		tupleIt = tuples->detach(tupleIt, r);
		mTuples.push_back(std::unique_ptr<Tuple>(r.release()));
	}
	if(person) {
		for(data_model::Person::ActivitiesIterator activity = person->getActivities().begin(); activity != person->getActivities().end();activity++) {
			mPerson.getActivities().push_back(*activity);
		}
	}

	/*for (pidf::Presence::PersonType::iterator domElement = extensions->begin(); domElement != extensions->end();
		 domElement++) {
		char * transcodedString = xercesc::XMLString::transcode(domElement->getNodeName());
		SLOGD << "Adding extension element  [" << transcodedString
			  << "] to presence info element [" << this << "]";
		xercesc::XMLString::release(&transcodedString);
		mExtensions.push_back(dynamic_cast<xercesc::DOMElement *>(mDomDocument->importNode(&*domElement, true)));
	}*/
}

static string generate_presence_id(void) {
	// code from linphone
	/*defined in http://www.w3.org/TR/REC-xml/*/
	static char presence_id_valid_characters[] = "0123456789abcdefghijklmnopqrstuvwxyz-.";
	/*NameStartChar (NameChar)**/
	static char presence_id_valid_start_characters[] = ":_abcdefghijklmnopqrstuvwxyz";
	char id[7];
	int i;
	id[0] = presence_id_valid_start_characters[belle_sip_random() % (sizeof(presence_id_valid_start_characters) - 1)];
	for (i = 1; i < 6; i++) {
		id[i] = presence_id_valid_characters[belle_sip_random() % (sizeof(presence_id_valid_characters) - 1)];
	}
	id[6] = '\0';

	return id;
}

void PresenceInformationElement::setExpiresTimer(belle_sip_source_t *timer) {
	if (mTimer) {
		// canceling previous timer
		belle_sip_source_cancel(mTimer);
		belle_sip_object_unref(mTimer);
	}
	mTimer = timer;

}
const std::unique_ptr<pidf::Tuple> &PresenceInformationElement::getTuple(const string &id) const {
	for (const std::unique_ptr<Tuple> &tup : mTuples) {
		if (tup->getId().compare(id) == 0)
			return tup;
	}
	throw FLEXISIP_EXCEPTION << "No tuple found for id [" << id << "]";
}
const list<std::unique_ptr<pidf::Tuple>> &PresenceInformationElement::getTuples() const {
	return mTuples;
}
const data_model::Person PresenceInformationElement::getPerson() const {
	return mPerson;
}
/*	void PresenceInformationElement::addTuple(pidf::Tuple* tup) {
		mTuples.push_back(tup);
	}
	void PresenceInformationElement::removeTuple(pidf::Tuple* tup) {
		mTuples.remove(tup);
	}*/
const string &PresenceInformationElement::getEtag() {
	return mEtag;
}
void PresenceInformationElement::setEtag(const string &eTag) {
	mEtag = eTag;
}

} /* namespace flexisip */
