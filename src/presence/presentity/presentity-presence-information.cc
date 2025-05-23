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

#include "presentity-presence-information.hh"

#include <functional>
#include <memory>
#include <ostream>

#include <belle-sip/belle-sip.h>

#include "flexisip/flexisip-exception.hh"
#include "flexisip/logmanager.hh"

#include "presence/presentity/presence-information-element.hh"
#include "presence/presentity/presentity-manager-interface.hh"
#include "presence/presentity/presentity-presence-information-listener.hh"
#include "utils/string-utils.hh"
#include "utils/xsd-utils.hh"
#include "xml/data-model.hh"
#include "xml/pidf+xml.hh"
#include "xml/rpid.hh"

#define ETAG_SIZE 8
using namespace std;
using namespace std::chrono;

namespace flexisip {

std::shared_ptr<PresentityPresenceInformation>
PresentityPresenceInformation::make(const belle_sip_uri_t* entity,
                                    PresentityManagerInterface& presentityManager,
                                    belle_sip_main_loop_t* mainloop,
                                    const PresenceStats& presenceStats,
                                    size_t maximumElementsNumber) {
	const auto sharedThis = std::shared_ptr<PresentityPresenceInformation>(
	    new PresentityPresenceInformation(entity, presentityManager, mainloop, presenceStats));
	sharedThis->mInformationElements = PresenceInformationElementMap::make(
	    mainloop, sharedThis, presenceStats.countPresenceElementMap, maximumElementsNumber);
	return sharedThis;
}

PresentityPresenceInformation::PresentityPresenceInformation(const belle_sip_uri_t* entity,
                                                             PresentityManagerInterface& presentityManager,
                                                             belle_sip_main_loop_t* mainloop,
                                                             const PresenceStats& presenceStats)
    : mEntity((belle_sip_uri_t*)belle_sip_object_clone(BELLE_SIP_OBJECT(entity))),
      mPresentityManager(presentityManager), mBelleSipMainloop(mainloop),
      mCountPresencePresentity(presenceStats.countPresencePresentity),
      mCountPresenceElement(presenceStats.countPresenceElement),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "PresentityPresenceInformation")) {
	belle_sip_object_ref(mainloop);
	belle_sip_object_ref((void*)mEntity);

	if (auto sharedCounter = mCountPresencePresentity.lock()) {
		sharedCounter->incrStart();
	} else {
		LOGE << "Failed to increment counter 'presence-presentity' (std::weak_ptr is empty)";
	}

	LOGD << "New instance created for uri [" << mEntity << "]";
}

PresentityPresenceInformation::~PresentityPresenceInformation() {
	mInformationElements.reset();
	belle_sip_object_unref((void*)mEntity);
	belle_sip_object_unref(mBelleSipMainloop);

	if (auto sharedCounter = mCountPresencePresentity.lock()) {
		sharedCounter->incrFinish();
	} else {
		LOGE << "Failed to increment counter 'presence-presentity-finished' (std::weak_ptr is empty)";
	}

	LOGD << "Destroyed instance";
}

size_t PresentityPresenceInformation::getNumberOfListeners() const {
	forEachSubscriber(
	    [](const shared_ptr<
	        PresentityPresenceInformationListener>&) { /*remove empty weak_ptr before returning the size*/ });

	return mSubscribers.size();
}

std::list<std::shared_ptr<PresentityPresenceInformationListener>> PresentityPresenceInformation::getListeners() const {
	list<shared_ptr<PresentityPresenceInformationListener>> retListeners;
	forEachSubscriber(
	    [&retListeners](const shared_ptr<PresentityPresenceInformationListener>& l) { retListeners.emplace_back(l); });
	return retListeners;
}

shared_ptr<PresentityPresenceInformationListener>
PresentityPresenceInformation::findPresenceInfoListener(const shared_ptr<PresentityPresenceInformation>& info,
                                                        bool calledFromMap) const {
	if (!calledFromMap) {
		return mInformationElements->findPresenceInfoListener(info);
	}

	return findSubscriber([&info](const shared_ptr<PresentityPresenceInformationListener>& l) {
		return belle_sip_uri_equals(l->getTo(), info->getEntity());
	});
}

string PresentityPresenceInformation::putTuples(Xsd::Pidf::Presence::TupleSequence& tuples,
                                                Xsd::DataModel::Person& person,
                                                int expires) {
	return setOrUpdate(&tuples, &person, nullopt, expires);
}

string PresentityPresenceInformation::updateTuples(Xsd::Pidf::Presence::TupleSequence& tuples,
                                                   Xsd::DataModel::Person& person,
                                                   const std::string& eTag,
                                                   int expires) {
	return setOrUpdate(&tuples, &person, eTag, expires);
}

string PresentityPresenceInformation::setOrUpdate(Xsd::Pidf::Presence::TupleSequence* tuples,
                                                  Xsd::DataModel::Person* person,
                                                  std::optional<const std::string> eTag,
                                                  int expires) {
	bool etagAlreadyPresent = false;

	if (eTag && !eTag->empty()) {
		if (etagAlreadyPresent = mInformationElements->isEtagPresent(*eTag); !etagAlreadyPresent) {
			stringstream message{};
			message << "unknown eTag [" << *eTag << "] for presentity [" << *this << "]";
			throw PresenceServerException{message.str()};
		}
		if (!tuples) {
			// just a refresh
			LOGD << "Updating presence information elem with ETag [" << *eTag << "] for presentity [" << *this << "]";
		} else {
			// remove
			mInformationElements->removeByEtag(*eTag, false);
			etagAlreadyPresent = false;
		}
	} else {
		// no etag, check for tuples
		if (!tuples) {
			stringstream message{};
			message << "cannot create information element for presentity [" << *this << "] without tuple";
			throw PresenceServerException{message.str()};
		}
	}

	// generate new etag
	char generatedETag_char[ETAG_SIZE];
	belle_sip_random_token(generatedETag_char, sizeof(generatedETag_char));
	string generatedETag = generatedETag_char;

	// cb function to invalidate an unrefreshed etag;
	auto func = [this, generatedETag](unsigned int) {
		// find information element
		LOGD_CTX(mLogPrefix, "setOrUpdate") << "ETag [" << generatedETag << "] has expired";
		this->removeTuplesForEtag(generatedETag);
		mPresentityManager.invalidateETag(generatedETag);
		return BELLE_SIP_STOP;
	};
	constexpr unsigned int valMax = numeric_limits<unsigned int>::max() / 1000U;
	unsigned int expiresMs = (static_cast<unsigned int>(expires) > valMax) ? numeric_limits<unsigned int>::max()
	                                                                       : static_cast<unsigned int>(expires) * 1000U;
	// create timer
	auto timer = belle_sip_main_loop_create_cpp_timeout(mBelleSipMainloop, func, expiresMs, "timer for presence Info");

	if (etagAlreadyPresent) {
		mPresentityManager.modifyEtag(*eTag, generatedETag);
		mInformationElements->refreshElement(*eTag, generatedETag, std::move(timer));
	} else {
		mPresentityManager.addEtag(shared_from_this(), generatedETag);
		auto informationElement =
		    make_unique<PresenceInformationElement>(tuples, person, generatedETag, timer, mCountPresenceElement);
		LOGD << "Presence information element [" << informationElement.get() << "] created for presentity [" << *this
		     << "]";
		// modify etag list for this presenceInfo and trigger notify on all listeners
		mInformationElements->emplace(generatedETag, std::move(informationElement));
	}

	LOGD << "Etag [" << generatedETag << "] associated to presentity [" << *this << "]";
	return generatedETag;
}

string PresentityPresenceInformation::refreshTuplesForEtag(const string& eTag, int expires) {
	return setOrUpdate(nullptr, nullptr, eTag, expires);
}

void PresentityPresenceInformation::setDefaultElement() {
	mDefaultInformationElement = make_shared<PresenceInformationElement>(getEntity(), mCountPresenceElement);
	notifyAll();
}

void PresentityPresenceInformation::setDefaultElement(const belle_sip_uri_t* newEntity) {
	mDefaultInformationElement = make_shared<PresenceInformationElement>(getEntity(), mCountPresenceElement);

	if (char* newEntityAsString = belle_sip_uri_to_string(newEntity)) {
		for (auto& tup : mDefaultInformationElement->getTuples()) {
			tup->setContact(Xsd::Pidf::Contact(newEntityAsString));
		}
		belle_sip_free(newEntityAsString);
	}

	mPresentityManager.handleLongtermPresence(newEntity, shared_from_this());
}

void PresentityPresenceInformation::removeTuplesForEtag(const string& eTag) {
	mInformationElements->removeByEtag(eTag);
}

ostream& operator<<(ostream& __os, const PresentityPresenceInformation& p) {
	return __os << "entity [" << p.getEntity() << "]/" << &p;
}

const belle_sip_uri_t* PresentityPresenceInformation::getEntity() const {
	return mEntity;
}

void PresentityPresenceInformation::addOrUpdateListener(
    const shared_ptr<PresentityPresenceInformationListener>& listener) {
	addOrUpdateListener(listener, -1);
}

void PresentityPresenceInformation::addListenerIfNecessary(
    const shared_ptr<PresentityPresenceInformationListener>& listener) {
	// search if exist
	const char* op;
	auto existing_listener = findSubscriber(
	    [&listener](const shared_ptr<PresentityPresenceInformationListener>& l) { return l == listener; });
	if (existing_listener) {
		op = "Updating";
	} else {
		// not found, adding
		mSubscribers.emplace_back(listener);
		op = "Adding";
	}
	LOGD << op << " listener [" << listener.get() << "] on [" << *this << "]";
}

void PresentityPresenceInformation::addOrUpdateListener(
    const shared_ptr<PresentityPresenceInformationListener>& listener, int expires) {

	addListenerIfNecessary(listener);

	if (expires > 0) {
		constexpr unsigned int valMax = numeric_limits<unsigned int>::max() / 1000U;
		unsigned int expiresMs = (static_cast<unsigned int>(expires) > valMax)
		                             ? numeric_limits<unsigned int>::max()
		                             : static_cast<unsigned int>(expires) * 1000U;

		// PresentityPresenceInformationListener* listener_ptr=listener.get();
		// cb function to invalidate an unrefreshed etag;
		auto func = [this, listener /*_ptr*/]([[maybe_unused]] unsigned int events) {
			LOGD_CTX(mLogPrefix, "addOrUpdateListener")
			    << "Listener [" << listener.get() << "] on [" << *this << "] has expired";
			listener->onExpired(*this);
			this->mPresentityManager.removeListener(listener);
			return BELLE_SIP_STOP;
		};

		// create timer
		auto timer = belle_sip_main_loop_create_cpp_timeout(mBelleSipMainloop, func, expiresMs,
		                                                    "timer for presence info listener");

		// set expiration timer
		listener->setExpiresTimer(mBelleSipMainloop, std::move(timer));
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

void PresentityPresenceInformation::removeListener(const shared_ptr<PresentityPresenceInformationListener>& listener) {
	LOGD << "Removing listener [" << listener.get() << "] on [" << *this << "]";
	// 1 cancel expiration time
	listener->setExpiresTimer(mBelleSipMainloop, nullptr);
	// 2 remove listener
	mSubscribers.remove_if([&listener](const weak_ptr<PresentityPresenceInformationListener>& wPtr) {
		auto l = wPtr.lock();
		return l == nullptr || l == listener;
	});
	//			 3.1.4.3. Unsubscribing
	//
	//			 Unsubscribing is handled in the same way as refreshing of a
	//			 subscription, with the "Expires" header set to "0".  Note that a
	//			 successful unsubscription will also trigger a final NOTIFY message.
	listener->onInformationChanged(*this, listener->extendedNotifyEnabled());
}

void PresentityPresenceInformation::addCapability(const std::string& capability) {
	if (mCapabilities.empty()) {
		mCapabilities = capability;
	} else if (mCapabilities.find(capability) == string::npos) {
		mCapabilities += ", " + capability;
		notifyAll();
	}
}

bool PresentityPresenceInformation::hasDefaultElement() const {
	return !!mDefaultInformationElement;
}

bool PresentityPresenceInformation::isKnown() const {
	return !mInformationElements->isEmpty() || hasDefaultElement();
}

string PresentityPresenceInformation::getPidf(bool extended) {
	stringstream out;
	try {
		char* entity = belle_sip_uri_to_string(getEntity());
		Xsd::Pidf::Presence presence((string(entity)));
		belle_sip_free(entity);
		list<string> tupleList;
		if (extended) {
			for (const auto& [eTag, infoElement] : mInformationElements->getElements()) {
				// copy pidf
				for (const unique_ptr<Xsd::Pidf::Tuple>& tup : infoElement->getTuples()) {
					// check for multiple tupple id, may happend with buggy presence publisher
					if (find(tupleList.begin(), tupleList.end(), tup->getId()) == tupleList.end()) {
						presence.getTuple().push_back(*tup);
						tupleList.push_back(tup->getId());
					} else {
						LOGI << "Already existing tuple id [" << tup->getId() << " for [" << *this << "], skipping";
					}
				}
				// copy extensions
				Xsd::DataModel::Person dm_person = infoElement->getPerson();
				for (const auto& activity : dm_person.getActivities()) {
					if (!presence.getPerson()) {
						auto person = Xsd::DataModel::Person(dm_person.getId());
						presence.setPerson(person);
					}
					presence.getPerson()->getActivities().push_back(activity);
				}

				/*
				 * We fill the person/timestamp field with the one found in tuples.
				 * If multiples tuples got the timestamp field we keep the most recent one,
				 * because this field should represent the date of last activity of the presentity.
				 */
				if (presence.getPerson()) {
					if (!presence.getPerson()->getTimestamp()) {
						presence.getPerson()->setTimestamp(dm_person.getTimestamp());
					} else if (dm_person.getTimestamp() &&
					           dm_person.getTimestamp().get() < presence.getPerson()->getTimestamp().get()) {
						presence.getPerson()->setTimestamp(dm_person.getTimestamp());
					}
				}
			}
		}
		if (mDefaultInformationElement) {
			// inserting default tuple
			Xsd::Pidf::Tuple* tup = mDefaultInformationElement->getTuples().begin()->get();
			auto predicate = [](char c) { return ::isspace(c) || c == '"'; };
			mCapabilities.erase(remove_if(mCapabilities.begin(), mCapabilities.end(), predicate), mCapabilities.end());
			vector<string> capabilityVector = StringUtils::split(mCapabilities, ",");

			for (const auto& capability : capabilityVector) {
				if (capability.empty()) continue;

				size_t pos = capability.find("/");
				const string& capabilityName = (pos == string::npos) ? capability : capability.substr(0, pos);
				const string& capabilityVersion = (pos == string::npos) ? "1.0" : capability.substr(pos + 1);
				if (const auto& it = mAddedCapabilities.find(capabilityName); it != mAddedCapabilities.cend()) {
					if (std::stof(it->second) >= std::stof(capabilityVersion)) continue;

					mAddedCapabilities.erase(it);
				}
				mAddedCapabilities.try_emplace(capabilityName, capabilityVersion);
			}
			for (const auto& cap : mAddedCapabilities) {
				Xsd::Pidf::Tuple::ServiceDescriptionType service(cap.first, cap.second);
				auto capaPredicate = [&cap](Xsd::Pidf::Tuple::ServiceDescriptionType serviceDescription) {
					return (cap.first == serviceDescription.getServiceId()) &&
					       (cap.second == serviceDescription.getVersion());
				};
				const auto& it = std::find_if(tup->getServiceDescription().begin(), tup->getServiceDescription().end(),
				                              capaPredicate);
				if (it == tup->getServiceDescription().end()) tup->getServiceDescription().push_back(service);
			}
			presence.getTuple().push_back(*tup);

			// copy extensions of default element, only if no elements were given previously.
			if (mInformationElements->isEmpty() || !extended) {
				Xsd::DataModel::Person dm_person = mDefaultInformationElement->getPerson();
				for (const auto& activity : dm_person.getActivities()) {
					if (!presence.getPerson()) {
						auto person = Xsd::DataModel::Person(dm_person.getId());
						presence.setPerson(person);
					}
					presence.getPerson()->getActivities().push_back(activity);
				}

				/*
				 * On tuple expiring mLastActivity is updated with the current timestamp.
				 * If the field presence/timestamp is not already filled and because all tuple for this
				 * presentity are already expired we filled it with the last activity timestamp.
				 */
				if (!presence.getPerson()->getTimestamp() && mInformationElements->getLastActivity()) {
					if (!presence.getPerson()) {
						auto person = Xsd::DataModel::Person(dm_person.getId());
						presence.setPerson(person);
					}
					time_t tt = system_clock::to_time_t(mInformationElements->getLastActivity().value());
					tm utc_tm;
					gmtime_r(&tt, &utc_tm);
					presence.getPerson()->setTimestamp(
					    Xsd::XmlSchema::DateTime(utc_tm.tm_year + 1900, utc_tm.tm_mon + 1, utc_tm.tm_mday,
					                             utc_tm.tm_hour, utc_tm.tm_min, utc_tm.tm_sec));
				}
			}
		}
		if (presence.getTuple().empty()) {
			Xsd::Pidf::Note value;
			Xsd::Namespace::Lang lang("en");
			value += "No presence information available yet";
			value.setLang(lang);
			presence.getNote().push_back(value);
		}

		// Serialize the object model to XML.
		//
		Xsd::XmlSchema::NamespaceInfomap map;
		map[""].name = "urn:ietf:params:xml:ns:pidf";

		serializePresence(out, presence, map);

	} catch (const Xsd::XmlSchema::Exception& e) {
		throw PresenceServerException{"failed to get pidf ("s + e.what() + ")"};
	} catch (const exception& e) {
		stringstream message{};
		message << "failed to get pidf for [" << *this << "] (" << e.what() << ")";
		throw PresenceServerException{message.str()};
	}

	return out.str();
}

void PresentityPresenceInformation::notifyAll() {
	forEachSubscriber([this](const shared_ptr<PresentityPresenceInformationListener>& listener) {
		listener->onInformationChanged(*this, listener->extendedNotifyEnabled());
	});
	LOGD << *this << " has notified [" << mSubscribers.size() << "] listeners";
}

std::shared_ptr<PresentityPresenceInformationListener> PresentityPresenceInformation::findSubscriber(
    const std::function<bool(const std::shared_ptr<PresentityPresenceInformationListener>&)>& predicate) const {
	for (auto it = mSubscribers.begin(); it != mSubscribers.end();) {
		auto subscriber = it->lock();
		if (subscriber == nullptr) {
			it = mSubscribers.erase(it);
			continue;
		}
		if (predicate(subscriber)) return subscriber;
		it++;
	}
	return nullptr;
}

void PresentityPresenceInformation::forEachSubscriber(
    const std::function<void(const std::shared_ptr<PresentityPresenceInformationListener>&)>& doFunc) const {
	std::queue<std::shared_ptr<PresentityPresenceInformationListener>> doFuncTargets;

	for (auto it = mSubscribers.begin(); it != mSubscribers.end();) {
		if (auto shared = it->lock()) {
			doFuncTargets.push(shared);
			it++;
		} else {
			it = mSubscribers.erase(it);
		}
	}

	while (!doFuncTargets.empty()) {
		doFunc(doFuncTargets.front());
		doFuncTargets.pop();
	}
}

void PresentityPresenceInformation::linkTo(const std::shared_ptr<PresentityPresenceInformation>& other) {
	mInformationElements->mergeInto(other->mInformationElements, false);
	mInformationElements = other->mInformationElements;

	forEachSubscriber([this](const auto& listener) {
		mPresentityManager.enableExtendedNotifyIfPossible(listener, shared_from_this());
	});
	other->forEachSubscriber([this](const auto& listener) {
		mPresentityManager.enableExtendedNotifyIfPossible(listener, shared_from_this());
	});

	mInformationElements->notifyListeners();
}

bool PresentityPresenceInformation::canBeSafelyDeleted() {
	return mInformationElements->isEmpty() && mInformationElements->getNumberOfListeners() == 0;
}

} /* namespace flexisip */