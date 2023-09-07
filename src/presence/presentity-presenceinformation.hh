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
#include <list>
#include <map>

#include <flexisip/flexisip-exception.hh>

#include "xml/pidf+xml.hh"

typedef struct _belle_sip_uri belle_sip_uri_t;
typedef struct belle_sip_source belle_sip_source_t;
typedef struct belle_sip_main_loop belle_sip_main_loop_t;
namespace flexisip {

/* Special deleter for belle_sip_source_t objects that cancels the timer in addition of
   decrementing the refcounter */
struct BelleSipSourceCancelingDeleter {
	constexpr BelleSipSourceCancelingDeleter() noexcept = default;
	constexpr BelleSipSourceCancelingDeleter(BelleSipObjectDeleter<belle_sip_source_t>&&) noexcept {
	}
	void operator()(belle_sip_source_t* source) noexcept {
		belle_sip_source_cancel(source);
		belle_sip_object_unref(source);
	}
};

class PresentityManager;
class PresenceInformationElement {
public:
	/* Re-definition of BelleSipSourcePtr in order to use BelleSipSourceCancelingDeleter as deleter */
	using BelleSipSourcePtr = std::unique_ptr<belle_sip_source_t, BelleSipSourceCancelingDeleter>;

	PresenceInformationElement(Xsd::Pidf::Presence::TupleSequence* tuples,
	                           Xsd::DataModel::Person* person,
	                           belle_sip_main_loop_t* mainLoop);
	// create an information element with a default tuple set to open.
	PresenceInformationElement(const belle_sip_uri_t* contact);
	~PresenceInformationElement();

	time_t getExpitationTime() const;

	template <typename T>
	void setExpiresTimer(T&& timer) {
		mTimer = std::forward<T>(timer);
	}

	const std::unique_ptr<Xsd::Pidf::Tuple>& getTuple(const std::string& id) const;
	const std::list<std::unique_ptr<Xsd::Pidf::Tuple>>& getTuples() const;
	const Xsd::DataModel::Person getPerson() const;
	// void addTuple(pidf::Tuple*);
	// void removeTuple(pidf::Tuple*);
	void clearTuples();
	const std::string& getEtag();
	void setEtag(const std::string& eTag);

private:
	std::list<std::unique_ptr<Xsd::Pidf::Tuple>> mTuples;
	Xsd::DataModel::Person mPerson{""};
	Xsd::XmlSchema::dom::unique_ptr<xercesc::DOMDocument> mDomDocument; // needed to store extension nodes
	belle_sip_main_loop_t* mBelleSipMainloop = nullptr;
	BelleSipSourcePtr mTimer;
	std::string mEtag;
};
/*
 * Presence Information is the key class representy a presentity. This class can be either created by a Publish for a
 presentiry or by a Subscription to a presentity

 */

class PresentityPresenceInformation;

class PresentityPresenceInformationListener {
public:
	/* Re-definition of BelleSipSourcePtr in order to use BelleSipSourceCancelingDeleter as deleter */
	using BelleSipSourcePtr = std::unique_ptr<belle_sip_source_t, BelleSipSourceCancelingDeleter>;

	PresentityPresenceInformationListener() = default;
	virtual ~PresentityPresenceInformationListener() = default;

	template <typename T>
	void setExpiresTimer(belle_sip_main_loop_t* ml, T&& timer) {
		mBelleSipMainloop = ml;
		mTimer = std::forward<T>(timer);
	}

	void enableExtendedNotify(bool enable);
	bool extendedNotifyEnabled();
	void enableBypass(bool enable);
	bool bypassEnabled();
	/*returns prsentity uri associated to this Listener*/
	virtual const belle_sip_uri_t* getPresentityUri() const = 0;
	virtual std::string getName() const {
		return "";
	}
	/*invoked on changes*/
	virtual void onInformationChanged(PresentityPresenceInformation& presenceInformation, bool extended) = 0;
	/*invoked on expiration*/
	virtual void onExpired(PresentityPresenceInformation& presenceInformation) = 0;
	virtual const belle_sip_uri_t* getFrom() = 0;
	virtual const belle_sip_uri_t* getTo() = 0;

private:
	belle_sip_main_loop_t* mBelleSipMainloop = nullptr;
	BelleSipSourcePtr mTimer;
	bool mExtendedNotify = false;
	bool mBypassEnabled = false;
};

class PresentityPresenceInformation : public std::enable_shared_from_this<PresentityPresenceInformation> {

public:
	PresentityPresenceInformation(const belle_sip_uri_t* entity,
	                              PresentityManager& presentityManager,
	                              belle_sip_main_loop_t* ml);
	virtual ~PresentityPresenceInformation();

	/*
	 * store tuples a new tupple;
	 * @return new eTag
	 * */
	std::string putTuples(Xsd::Pidf::Presence::TupleSequence& tuples, Xsd::DataModel::Person& person, int expires);

	void setDefaultElement(const char* contact = NULL);

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
	                         std::string& eTag,
	                         int expires);

	/*
	 * refresh a publish
	 * @return new eTag
	 * */
	std::string refreshTuplesForEtag(const std::string& eTag, int expires);

	/*
	 * refresh a publish
	 * */
	void removeTuplesForEtag(const std::string& eTag);

	const belle_sip_uri_t* getEntity() const;

	const std::string& getName() {
		return mName;
	}
	void setName(const std::string& name) {
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
	bool isKnown();

	/*
	 * return true if a presence info has a default presence value previously set by setDefaultElement
	 */
	bool hasDefaultElement();

	/*
	 * return number of current listeners (I.E subscriber)
	 */
	size_t getNumberOfListeners() const;

	/*
	 * return current number of information elements (I.E from PUBLISH)
	 */
	size_t getNumberOfInformationElements() const;

	/*
	 * return all the listeners (I.E. subscribers) of this presence information
	 */
	std::list<std::shared_ptr<PresentityPresenceInformationListener>> getListeners() const;

	/*
	 * return if one of the subscribers subscribed for a presence information
	 */
	std::shared_ptr<PresentityPresenceInformationListener>
	findPresenceInfoListener(std::shared_ptr<PresentityPresenceInformation>& info);

private:
	PresentityPresenceInformation(const PresentityPresenceInformation& other);
	/*
	 * tuples may be null
	 */
	std::string setOrUpdate(Xsd::Pidf::Presence::TupleSequence* tuples,
	                        Xsd::DataModel::Person*,
	                        const std::string* eTag,
	                        int expires);

	/*
	 *Notify all listener
	 */
	void notifyAll();

	std::shared_ptr<PresentityPresenceInformationListener>
	findSubscriber(std::function<bool(const std::shared_ptr<PresentityPresenceInformationListener>&)> predicate) const;
	void
	forEachSubscriber(std::function<void(const std::shared_ptr<PresentityPresenceInformationListener>&)> doFunc) const;

	const belle_sip_uri_t* mEntity;
	PresentityManager& mPresentityManager;
	belle_sip_main_loop_t* mBelleSipMainloop;
	// Tuples ordered by Etag.
	std::map<std::string /*Etag*/, PresenceInformationElement*> mInformationElements;

	// list of subscribers function to be called when a tuple changed
	mutable std::list<std::weak_ptr<PresentityPresenceInformationListener>> mSubscribers;
	std::shared_ptr<PresenceInformationElement> mDefaultInformationElement; // purpose of this element is to have a
	                                                                        // default presence status (I.E closed)
	                                                                        // when all publish have expired.
	std::string mName;
	std::string mCapabilities;
	std::map<std::string, std::string> mAddedCapabilities;
	std::optional<std::chrono::system_clock::time_point> mLastActivity = std::nullopt;
	BelleSipSourcePtr mLastActivityTimer = nullptr;
};

std::ostream& operator<<(std::ostream& __os, const PresentityPresenceInformation&);
FlexisipException& operator<<(FlexisipException& ex, const PresentityPresenceInformation&);

} /* namespace flexisip */
