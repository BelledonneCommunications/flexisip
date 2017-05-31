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

#ifndef PRESENCETUPLE_HH_
#define PRESENCETUPLE_HH_

#include <map>
#include "pidf+xml.hxx"
//#include "data-model.hxx"
#include <list>
#include "utils/flexisip-exception.hh"

typedef struct _belle_sip_uri belle_sip_uri_t;
typedef struct belle_sip_source belle_sip_source_t;
typedef struct belle_sip_main_loop belle_sip_main_loop_t;
using namespace std;
namespace flexisip {
class PresentityManager;
class PresenceInformationElement {
  public:
	PresenceInformationElement(pidf::Presence::TupleSequence *tuples, data_model::Person *person,
							   belle_sip_main_loop_t *mainLoop);
	// create an information element with a default tuple set to closed.
	PresenceInformationElement(const belle_sip_uri_t *contact);
	~PresenceInformationElement();
	time_t getExpitationTime() const;
	void setExpiresTimer(belle_sip_source_t *timer);
	const std::unique_ptr<pidf::Tuple> &getTuple(const string &id) const;
	const list<std::unique_ptr<pidf::Tuple>> &getTuples() const;
	const data_model::Person getPerson() const;
	// void addTuple(pidf::Tuple*);
	// void removeTuple(pidf::Tuple*);
	void clearTuples();
	const string &getEtag();
	void setEtag(const string &eTag);

  private:
	list<std::unique_ptr<pidf::Tuple>> mTuples;
	data_model::Person mPerson = data_model::Person("");
	::xml_schema::dom::unique_ptr<xercesc::DOMDocument> mDomDocument; // needed to store extension nodes
	belle_sip_main_loop_t *mBelleSipMainloop;
	belle_sip_source_t *mTimer;
	string mEtag;
};
/*
 * Presence Information is the key class representy a presentity. This class can be either created bu a Publish for a
 presentiry or by a Subscription to a presentity

 */

class PresentityPresenceInformation;

class PresentityPresenceInformationListener  {

  public:
	PresentityPresenceInformationListener();
	virtual ~PresentityPresenceInformationListener();
	void setExpiresTimer(belle_sip_main_loop_t *ml, belle_sip_source_t *timer);
	void enableExtendedNotify(bool enable);
	bool extendedNotifyEnabled();
	void enableBypass(bool enable);
	bool bypassEnabled();
	/*returns prsentity uri associated to this Listener*/
	virtual const belle_sip_uri_t *getPresentityUri() const = 0;
	/*invoked on changes*/
	virtual void onInformationChanged(PresentityPresenceInformation &presenceInformation, bool extended) = 0;
	/*invoked on expiration*/
	virtual void onExpired(PresentityPresenceInformation &presenceInformation) = 0;
	virtual const belle_sip_uri_t* getFrom() = 0;
	virtual const belle_sip_uri_t* getTo() = 0;
  private:
	belle_sip_main_loop_t *mBelleSipMainloop;
	belle_sip_source_t *mTimer;
	bool mExtendedNotify;
	bool mBypassEnabled;
};

class PresentityPresenceInformation : public std::enable_shared_from_this<PresentityPresenceInformation> {

  public:
	PresentityPresenceInformation(const belle_sip_uri_t *entity, PresentityManager &presentityManager, belle_sip_main_loop_t *ml);
	virtual ~PresentityPresenceInformation();

	/*
	 * store tuples a new tupple;
	 * @return new eTag
	 * */
	string putTuples(pidf::Presence::TupleSequence &tuples, data_model::Person &person, int expires);

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
	string updateTuples(pidf::Presence::TupleSequence &tuples, data_model::Person &person, string &eTag,
						int expires) throw(FlexisipException);

	/*
	 * refresh a publish
	 * @return new eTag
	 * */
	string refreshTuplesForEtag(const string &eTag, int expires) throw(FlexisipException);

	/*
	* refresh a publish
	* */
	void removeTuplesForEtag(const string &eTag);

	const belle_sip_uri_t *getEntity() const;

	/**
	 *add notity listener for an entity
	 */
	void addOrUpdateListener(const shared_ptr<PresentityPresenceInformationListener> &listener, int expires);

	/**
	 *add notity listener for an entity without expiration timer
	 */
	void addOrUpdateListener(const shared_ptr<PresentityPresenceInformationListener> &listener);
	void addListenerIfNecessary(const shared_ptr<PresentityPresenceInformationListener> &listener);
	/*
	 * remove listener
	 */
	void removeListener(const shared_ptr<PresentityPresenceInformationListener> &listener);

	/*
	 * return the presence information for this entity in a pidf serilized format
	 */
	string getPidf(bool extended) throw(FlexisipException);

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
	std::list<shared_ptr<PresentityPresenceInformationListener>> getListeners() const;

	/*
	 * return if one of the subscribers subscribed for a presence information
	 */
	bool findPresenceInfo(std::shared_ptr<PresentityPresenceInformation> &info);

  private:
	PresentityPresenceInformation(const PresentityPresenceInformation& other);
	/*
	 * tuples may be null
	 */
	string setOrUpdate(pidf::Presence::TupleSequence *tuples, data_model::Person *, const string *eTag,
					   int expires) throw(FlexisipException);
	/*
	 *Notify all listener
	 */
	void notifyAll();

	const belle_sip_uri_t *mEntity;
	PresentityManager &mPresentityManager;
	belle_sip_main_loop_t *mBelleSipMainloop;
	// Tuples ordered by Etag.
	std::map<std::string /*Etag*/, PresenceInformationElement *> mInformationElements;

	// list of subscribers function to be called when a tuple changed
	std::list<shared_ptr<PresentityPresenceInformationListener>> mSubscribers;
	std::shared_ptr<PresenceInformationElement> mDefaultInformationElement; // purpose of this element is to have a
																			// default presence status (I.E closed) when
																			// all publish have expired.
};

std::ostream &operator<<(std::ostream &__os, const PresentityPresenceInformation &);
FlexisipException &operator<<(FlexisipException &ex, const PresentityPresenceInformation &);

} /* namespace flexisip */

#endif /* PRESENCETUPLE_HH_ */
