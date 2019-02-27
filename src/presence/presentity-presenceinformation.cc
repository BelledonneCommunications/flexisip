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

#include <functional>
#include <memory>
#include <ostream>

#include "belle-sip/belle-sip.h"

#include "data-model.hh"
#include "etag-manager.hh"
#include <flexisip/logmanager.hh>
#include "pidf+xml.hh"
#include "presentity-manager.hh"
#include "presentity-presenceinformation.hh"
#include "rpid.hh"
#include <flexisip/flexisip-exception.hh>
#include "utils/string-utils.hh"

#define ETAG_SIZE 8
using namespace std;

namespace flexisip {

static string generate_presence_id(void);

FlexisipException &operator<<(FlexisipException &e, const Xsd::XmlSchema::Exception &val) {
	stringstream e_out;
	e_out << val;
	e << e_out.str();
	return e;
}

PresenceInformationElement::PresenceInformationElement(const belle_sip_uri_t *contact)
	: mTuples(), mDomDocument(::xsd::cxx::xml::dom::create_document<char>()), mBelleSipMainloop(nullptr), mTimer(nullptr) {
	char *contact_as_string = belle_sip_uri_to_string(contact);
	time_t t;
	time(&t);
	struct tm *now = gmtime(&t);
	Xsd::Pidf::Status status;
	status.setBasic(Xsd::Pidf::Basic("open"));
	unique_ptr<Xsd::Pidf::Tuple> tup(new Xsd::Pidf::Tuple(status, string(generate_presence_id())));
	tup->setTimestamp(Xsd::XmlSchema::DateTime(now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour,
											 now->tm_min, now->tm_sec));
	tup->setContact(Xsd::Pidf::Contact(contact_as_string));
	mTuples.clear(); // just in case
	mTuples.push_back(unique_ptr<Xsd::Pidf::Tuple>(tup.release()));
	Xsd::Rpid::Activities act = Xsd::Rpid::Activities();
	act.getAway().push_back(Xsd::Rpid::Empty());
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
		setExpiresTimer(nullptr);

	SLOGD << "Presence information element [" << this << "] deleted";
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
list<shared_ptr<PresentityPresenceInformationListener>> PresentityPresenceInformation::getListeners() const {
	return mSubscribers;
}
size_t PresentityPresenceInformation::getNumberOfInformationElements() const {
	return mInformationElements.size();
}
bool PresentityPresenceInformation::findPresenceInfo(shared_ptr<PresentityPresenceInformation> &info) {
	for (shared_ptr<PresentityPresenceInformationListener> listener : mSubscribers) {
		if(belle_sip_uri_equals(listener->getTo(), info->getEntity())) {
			return true;
		}
	}
	return false;
}
string PresentityPresenceInformation::putTuples(Xsd::Pidf::Presence::TupleSequence &tuples,
												Xsd::DataModel::Person &person, int expires) {
	return setOrUpdate(&tuples, &person, nullptr, expires);
}

string PresentityPresenceInformation::updateTuples(Xsd::Pidf::Presence::TupleSequence &tuples,
												   Xsd::DataModel::Person  &person, string &eTag,
												   int expires) {
	return setOrUpdate(&tuples, &person, &eTag, expires);
}
void PresenceInformationElement::clearTuples() {
	mTuples.clear();
}

string PresentityPresenceInformation::setOrUpdate(Xsd::Pidf::Presence::TupleSequence *tuples,
												  Xsd::DataModel::Person  *person, const string *eTag,
												  int expires) {
	PresenceInformationElement *informationElement = nullptr;
	constexpr unsigned int valMax = numeric_limits<unsigned int>::max() / 1000U;
	unsigned int expiresMs;

	// etag ?
	if (eTag && eTag->size() > 0) {
		// check if already exist
		auto it = mInformationElements.find(*eTag);
		if (it == mInformationElements.end())
			throw FLEXISIP_EXCEPTION << "Unknown eTag [" << *eTag << "] for presentity [" << *this << "]";
		if (!tuples) {
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
		if (!tuples)
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


	expiresMs = (static_cast<unsigned int>(expires) > valMax) ? numeric_limits<unsigned int>::max() : static_cast<unsigned int>(expires) * 1000U;

	// create timer
	belle_sip_source_t *timer = belle_sip_main_loop_create_cpp_timeout(  mBelleSipMainloop
																	   , func
																	   , expiresMs
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

string PresentityPresenceInformation::refreshTuplesForEtag(const string &eTag, int expires) {
	return setOrUpdate(nullptr, nullptr, &eTag, expires);
}

void PresentityPresenceInformation::setDefaultElement(const char *contact) {
	mDefaultInformationElement = make_shared<PresenceInformationElement>(getEntity());

	if (contact) {
		for (auto &tup : mDefaultInformationElement->getTuples()) {
			tup->setContact(Xsd::Pidf::Contact(contact));
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
ostream &operator<<(ostream &__os, const PresentityPresenceInformation &p) {
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
		constexpr unsigned int valMax = numeric_limits<unsigned int>::max() / 1000U;
		unsigned int expiresMs = (static_cast<unsigned int>(expires) > valMax) ? numeric_limits<unsigned int>::max() : static_cast<unsigned int>(expires) * 1000U;

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
																		   , expiresMs, "timer for presence info listener");

		// set expiration timer
		listener->setExpiresTimer(mBelleSipMainloop, timer);
	} else {
		listener->setExpiresTimer(mBelleSipMainloop, nullptr);
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
	listener->setExpiresTimer(mBelleSipMainloop, nullptr);
	// 2 remove listener
	mSubscribers.remove(listener);
	//			 3.1.4.3. Unsubscribing
	//
	//			 Unsubscribing is handled in the same way as refreshing of a
	//			 subscription, with the "Expires" header set to "0".  Note that a
	//			 successful unsubscription will also trigger a final NOTIFY message.
	listener->onInformationChanged(*this, listener->extendedNotifyEnabled());
}

void PresentityPresenceInformation::addCapability(const std::string &capability) {
	if (mCapabilities.empty()) {
		mCapabilities = capability;
	} else if (mCapabilities.find(capability) == mCapabilities.npos) {
		mCapabilities += ", " + capability;
	}
	notifyAll();
}

bool PresentityPresenceInformation::hasDefaultElement() {
	return !!mDefaultInformationElement;
}
bool PresentityPresenceInformation::isKnown() {
	return mInformationElements.size() > 0 || hasDefaultElement();
}
string PresentityPresenceInformation::getPidf(bool extended) {
	stringstream out;
	try {
		char *entity = belle_sip_uri_to_string(getEntity());
		Xsd::Pidf::Presence presence((string(entity)));
		belle_sip_free(entity);
		list<string> tupleList;
		if(extended) {
			for (const auto &element : mInformationElements) {
				// copy pidf
				for (const unique_ptr<Xsd::Pidf::Tuple> &tup : element.second->getTuples()) {
					// check for multiple tupple id, may happend with buggy presence publisher
					if (find(tupleList.begin(), tupleList.end(), tup.get()->getId()) == tupleList.end()) {
						auto predicate = [](char c){ return ::isspace(c) || c == '"'; };
						mCapabilities.erase(remove_if(mCapabilities.begin(), mCapabilities.end(), predicate), mCapabilities.end());
						vector<string> capabilityVector = StringUtils::split(mCapabilities, ",");
						bool addService = false;
						for (const auto &capability : capabilityVector) {
							if (capability.empty()) continue;

							size_t pos = capability.find("/");
							const string &capabilityName = (pos == string::npos) ? capability : capability.substr(0, pos);
							const string &capabilityVersion = (pos == string::npos) ? "1.0" : capability.substr(pos + 1);
							const auto &it = mAddedCapabilities.find(capabilityName);
							if(it != mAddedCapabilities.cend()) {
								if (std::stof(it->second) >= std::stof(capabilityVersion))
									continue;

								mAddedCapabilities.erase(it);
							}
							addService = true;
							mAddedCapabilities.insert(make_pair(capabilityName, capabilityVersion));
						}
						if (addService) {
							for (const auto &cap : mAddedCapabilities) {
								Xsd::Pidf::Tuple::ServiceDescriptionType service(cap.first, cap.second);
								tup->getServiceDescription().push_back(service);
							}
						}
						presence.getTuple().push_back(*tup);
						tupleList.push_back(tup.get()->getId());
					} else {
						SLOGW << "Already existing tuple id [" << tup.get()->getId() << " for [" << *this << "], skipping";
					}
				}
				// copy extensions
				Xsd::DataModel::Person dm_person = element.second->getPerson();
				for(Xsd::DataModel::Person::ActivitiesIterator activity = dm_person.getActivities().begin(); activity != dm_person.getActivities().end();activity++) {
					if(!presence.getPerson()) {
						Xsd::DataModel::Person person = Xsd::DataModel::Person(dm_person.getId());
						presence.setPerson(person);
					}
					presence.getPerson()->getActivities().push_back(*activity);
				}
			}
		}
		if ((mInformationElements.size() == 0 || !extended) && mDefaultInformationElement) {
			// insering default tuple
			Xsd::Pidf::Tuple *tup = mDefaultInformationElement->getTuples().begin()->get();
			auto predicate = [](char c){ return ::isspace(c) || c == '"'; };
			mCapabilities.erase(remove_if(mCapabilities.begin(), mCapabilities.end(), predicate), mCapabilities.end());
			vector<string> capabilityVector = StringUtils::split(mCapabilities, ",");
			bool addService = false;
			for (const auto &capability : capabilityVector) {
				if (capability.empty()) continue;

				size_t pos = capability.find("/");
				const string &capabilityName = (pos == string::npos) ? capability : capability.substr(0, pos);
				const string &capabilityVersion = (pos == string::npos) ? "1.0" : capability.substr(pos + 1);
				const auto &it = mAddedCapabilities.find(capabilityName);
				if(it != mAddedCapabilities.cend()) {
					if (std::stof(it->second) >= std::stof(capabilityVersion))
						continue;

					mAddedCapabilities.erase(it);
				}
				addService = true;
				mAddedCapabilities.insert(make_pair(capabilityName, capabilityVersion));
			}
			if (addService) {
				for (const auto &cap : mAddedCapabilities) {
					Xsd::Pidf::Tuple::ServiceDescriptionType service(cap.first, cap.second);
					auto predicate= [cap](Xsd::Pidf::Tuple::ServiceDescriptionType serviceDescription) {
						return (cap.first == serviceDescription.getServiceId()) && (cap.second == serviceDescription.getVersion());
					};
					const auto &it = std::find_if(tup->getServiceDescription().begin(), tup->getServiceDescription().end(), predicate);
					if (it == tup->getServiceDescription().end())
						tup->getServiceDescription().push_back(service);
				}
			}
			presence.getTuple().push_back(*tup);

			// copy extensions
			Xsd::DataModel::Person dm_person = mDefaultInformationElement->getPerson();
			for(Xsd::DataModel::Person::ActivitiesIterator activity = dm_person.getActivities().begin(); activity != dm_person.getActivities().end();activity++) {
				if(!presence.getPerson()) {
					Xsd::DataModel::Person person = Xsd::DataModel::Person(dm_person.getId());
					presence.setPerson(person);
				}
				presence.getPerson()->getActivities().push_back(*activity);
			}
		}
		if (presence.getTuple().size() == 0) {
			Xsd::Pidf::Note value;
			namespace_::Lang lang("en");
			value += "No presence information available yet";
			value.setLang(lang);
			// value.lang("en");
			presence.getNote().push_back(value);
		}

		// Serialize the object model to XML.
		//
		Xsd::XmlSchema::NamespaceInfomap map;
		map[""].name = "urn:ietf:params:xml:ns:pidf";

		serializePresence(out, presence, map);

	} catch (const Xsd::XmlSchema::Exception &e) {
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
PresentityPresenceInformationListener::PresentityPresenceInformationListener() : mTimer(nullptr), mExtendedNotify(false), mBypassEnabled(false) {
}
PresentityPresenceInformationListener::~PresentityPresenceInformationListener() {
	setExpiresTimer(mBelleSipMainloop, nullptr);
}
bool PresentityPresenceInformationListener::extendedNotifyEnabled() {
	return mExtendedNotify;
}
void PresentityPresenceInformationListener::enableExtendedNotify(bool enable) {
	mExtendedNotify = bypassEnabled() || enable;
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

PresenceInformationElement::PresenceInformationElement(Xsd::Pidf::Presence::TupleSequence *tuples,
													   Xsd::DataModel::Person *person,
													   belle_sip_main_loop_t *mainLoop)
	: mDomDocument(::xsd::cxx::xml::dom::create_document<char>()), mBelleSipMainloop(mainLoop), mTimer(nullptr) {

	for (Xsd::Pidf::Presence::TupleSequence::iterator tupleIt = tuples->begin(); tupleIt != tuples->end();) {
		SLOGD << "Adding tuple id [" << tupleIt->getId() << "] to presence info element [" << this << "]";
		unique_ptr<Xsd::Pidf::Tuple> r;
		tupleIt = tuples->detach(tupleIt, r);
		mTuples.push_back(unique_ptr<Xsd::Pidf::Tuple>(r.release()));
	}
	if(person) {
		for(Xsd::DataModel::Person::ActivitiesIterator activity = person->getActivities().begin(); activity != person->getActivities().end();activity++) {
			mPerson.getActivities().push_back(*activity);
		}
	}

	/*for (Xsd::Pidf::Presence::PersonType::iterator domElement = extensions->begin(); domElement != extensions->end();
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
const unique_ptr<Xsd::Pidf::Tuple> &PresenceInformationElement::getTuple(const string &id) const {
	for (const unique_ptr<Xsd::Pidf::Tuple> &tup : mTuples) {
		if (tup->getId().compare(id) == 0)
			return tup;
	}
	throw FLEXISIP_EXCEPTION << "No tuple found for id [" << id << "]";
}
const list<unique_ptr<Xsd::Pidf::Tuple>> &PresenceInformationElement::getTuples() const {
	return mTuples;
}
const Xsd::DataModel::Person PresenceInformationElement::getPerson() const {
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
