/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include "compat/optional.hh"
#include <chrono>
#include <list>
#include <map>

#include <belle-sip/belle-sip.h>
#include <memory>

#include "flexisip/flexisip-exception.hh"

#include "presence/belle-sip-using.hh"
#include "presence/presentity/presence-information-element-map.hh"

namespace flexisip {

class PresentityManager;

/**
 * Presence Information is the key class representing a presentity. This class can be either created by a Publish for a
 * presentity or by a Subscription to a presentity
 */
class PresentityPresenceInformation : public std::enable_shared_from_this<PresentityPresenceInformation>,
                                      public ElementMapListener {

public:
	static std::shared_ptr<PresentityPresenceInformation>
	make(const belle_sip_uri_t* entity, PresentityManager& presentityManager, belle_sip_main_loop_t* ml);
	~PresentityPresenceInformation() override;

	/*
	 * store tuples a new tupple;
	 * @return new eTag
	 * */
	std::string putTuples(Xsd::Pidf::Presence::TupleSequence& tuples, Xsd::DataModel::Person& person, int expires);

	void setDefaultElement();

	void setDefaultElement(const belle_sip_uri_t* newEntity);
	/*
	 *
	 * Update tuples attached to an eTag
	 *
	 * rfc3903
	 * 4.4.  Modifying Event State
	 * ...
	 * If the entity-tag matches previously
	 * published event state at the ESC, that event state is replaced by the
	 * event state carried in the PUBLISH request, and the EPA receives a
	 * 2xx response.
	 *
	 * @return new eTag
	 * */
	std::string updateTuples(Xsd::Pidf::Presence::TupleSequence& tuples,
	                         Xsd::DataModel::Person& person,
	                         const std::string& eTag,
	                         int expires);

	/**
	 * Refresh a publish
	 * @return new eTag
	 *
	 */
	std::string refreshTuplesForEtag(const std::string& eTag, int expires);

	/*
	 * refresh a publish
	 * */
	void removeTuplesForEtag(const std::string& eTag);

	const belle_sip_uri_t* getEntity() const;

	const std::string& getName() const {
		return mName;
	}
	void setName(std::string_view name) {
		mName = name;
	}
	void addCapability(const std::string& capability);

	/**
	 *add notity listener for an entity
	 */
	void addOrUpdateListener(const std::shared_ptr<PresentityPresenceInformationListener>& listener, int expires);

	/**
	 *add notity listener for an entity without expiration timer
	 */
	void addOrUpdateListener(const std::shared_ptr<PresentityPresenceInformationListener>& listener);
	void addListenerIfNecessary(const std::shared_ptr<PresentityPresenceInformationListener>& listener);
	/*
	 * remove listener
	 */
	void removeListener(const std::shared_ptr<PresentityPresenceInformationListener>& listener);

	/*
	 * return the presence information for this entity in a pidf serilized format
	 */
	std::string getPidf(bool extended);

	/*
	 * return true if a presence info is already known from a publish
	 */
	bool isKnown() const;

	/*
	 * return true if a presence info has a default presence value previously set by setDefaultElement
	 */
	bool hasDefaultElement() const;

	/*
	 * return number of current listeners (I.E subscriber)
	 */
	size_t getNumberOfListeners() const;

	/*
	 * return all the listeners (I.E. subscribers) of this presence information
	 */
	std::list<std::shared_ptr<PresentityPresenceInformationListener>> getListeners() const;

	/*
	 * return if one of the subscribers subscribed for a presence information
	 */
	std::shared_ptr<PresentityPresenceInformationListener>
	findPresenceInfoListener(const std::shared_ptr<PresentityPresenceInformation>& info,
	                         bool calledFromMap = false) const;

	void onMapUpdate() override {
		notifyAll();
	}

	void linkTo(const std::shared_ptr<PresentityPresenceInformation>& other);

	/*
	 * Return true if no tuple are present in ElementMap, and no more listener are present across all map's parent.
	 */
	bool canBeSafelyDeleted();

private:
	PresentityPresenceInformation(const belle_sip_uri_t* entity,
	                              PresentityManager& presentityManager,
	                              belle_sip_main_loop_t* ml);
	PresentityPresenceInformation(const PresentityPresenceInformation& other);
	/*
	 * tuples may be null
	 */
	std::string setOrUpdate(Xsd::Pidf::Presence::TupleSequence* tuples,
	                        Xsd::DataModel::Person* person,
	                        std::optional<const std::string> eTag,
	                        int expires);

	/*
	 *Notify all listener
	 */
	void notifyAll();

	std::shared_ptr<PresentityPresenceInformationListener> findSubscriber(
	    const std::function<bool(const std::shared_ptr<PresentityPresenceInformationListener>&)>& predicate) const;
	void forEachSubscriber(
	    const std::function<void(const std::shared_ptr<PresentityPresenceInformationListener>&)>& doFunc) const;

	const belle_sip_uri_t* mEntity;
	PresentityManager& mPresentityManager;
	belle_sip_main_loop_t* mBelleSipMainloop;

	// Tuples ordered by Etag.
	std::shared_ptr<PresenceInformationElementMap> mInformationElements{};

	// list of subscribers function to be called when a tuple changed
	mutable std::list<std::weak_ptr<PresentityPresenceInformationListener>> mSubscribers;
	std::shared_ptr<PresenceInformationElement> mDefaultInformationElement; // purpose of this element is to have a
	                                                                        // default presence status (I.E closed)
	                                                                        // when all publish have expired.
	std::string mName;
	std::string mCapabilities;
	std::unordered_map<std::string, std::string> mAddedCapabilities;
};

std::ostream& operator<<(std::ostream& __os, const PresentityPresenceInformation&);
FlexisipException& operator<<(FlexisipException& ex, const PresentityPresenceInformation&);

} /* namespace flexisip */
