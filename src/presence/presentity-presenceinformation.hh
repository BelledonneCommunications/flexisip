/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2014  Belledonne Communications SARL.
 
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
#include "flexisip-exception.hh"

typedef struct _belle_sip_uri belle_sip_uri_t;
typedef struct belle_sip_source belle_sip_source_t;
typedef struct belle_sip_main_loop belle_sip_main_loop_t;
using namespace std;
namespace flexisip {
class EtagManager;
class PresenceInformationElement {
public:
	PresenceInformationElement(pidf::Presence::TupleSequence* tuples, pidf::Presence::AnySequence* extensions, belle_sip_main_loop_t* mainLoop);
	~PresenceInformationElement();
	time_t getExpitationTime() const;
	void setExpiresTimer( belle_sip_source_t* timer);
	const std::unique_ptr<pidf::Tuple>& getTuple(const string& id) const;
	const list<std::unique_ptr<pidf::Tuple>>& getTuples() const;
	const list<xercesc::DOMElement*> getExtensions() const;
	//void addTuple(pidf::Tuple*);
	//void removeTuple(pidf::Tuple*);
	void clearTuples();
	const string& getEtag();
	void setEtag(const string& eTag);
private:
	list<std::unique_ptr<pidf::Tuple>> mTuples;
	list<xercesc::DOMElement*> mExtensions;
	::xml_schema::dom::unique_ptr< ::xercesc::DOMDocument > mDomDocument; //needed to store extension nodes
	belle_sip_main_loop_t* mBelleSipMainloop;
	belle_sip_source_t* mTimer;
	string mEtag;
};
/*
 * Presence Information is the key class representy a presentity. This class can be either created bu a Publish for a presentiry or by a Subscription to a presentity
 
 */

	class PresentityPresenceInformation;
	
	class PresentityPresenceInformationListener {
		
	public:
		PresentityPresenceInformationListener();
		~PresentityPresenceInformationListener();
		void setExpiresTimer(belle_sip_main_loop_t *ml,belle_sip_source_t* timer);
		/*returns prsentity uri associated to this Listener*/
		virtual const belle_sip_uri_t* getPresentityUri()=0;
		/*invoked on changes*/
		virtual void onInformationChanged(PresentityPresenceInformation& presenceInformation)=0;
		/*invoked on expiration*/
		virtual void onExpired(PresentityPresenceInformation& presenceInformation)=0;
	private:
		belle_sip_source_t* mTimer;
	};
	
	
	
	
	class PresentityPresenceInformation : public std::enable_shared_from_this<PresentityPresenceInformation>{

public:

	/*
	 * store tuples a new tupple;
	 * @return new eTag
	 * */
	string  putTuples(pidf::Presence::TupleSequence& tuples, pidf::Presence::AnySequence& extensions, int expires);

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
	string  updateTuples(pidf::Presence::TupleSequence& tuples, pidf::Presence::AnySequence& extensions, string& eTag, int expires) throw (FlexisipException);

	/*
	 * refresh a publish
	 * @return new eTag
	 * */
	string refreshTuplesForEtag(const string& eTag,int expires) throw (FlexisipException);

	/*
	* refresh a publish
	* */
	void removeTuplesForEtag(const string& eTag);



	PresentityPresenceInformation(const belle_sip_uri_t* entity,EtagManager& etagManager,belle_sip_main_loop_t *ml);
	virtual ~PresentityPresenceInformation();

	const belle_sip_uri_t* getEntity() const;

	/**
	 *add notity listener for an entity
	 */
	void addOrUpdateListener(PresentityPresenceInformationListener& listener,int expires);
	/*
	 * remove listener
	 */
	void removeListener(PresentityPresenceInformationListener& listener);
	
	
	/*
	 * return the presence information for this entity in a pidf serilized format
	 */
	string getPidf() throw (FlexisipException);
	
	

private:
	/*
	 * tuples may be null
	 */
	string setOrUpdate(pidf::Presence::TupleSequence* tuples, pidf::Presence::AnySequence*, const string* eTag,int expires) throw (FlexisipException);
	/*
	 *Notify all listener
	 */
	void notifyAll();
	
	const belle_sip_uri_t* mEntity;
	EtagManager& mEtagManager;
	belle_sip_main_loop_t* mBelleSipMainloop;
	//Tuples ordered by Etag.
	std::map<std::string /*Etag*/,PresenceInformationElement*> mInformationElements;

	// list of subscribers function to be called when a tuple changed
	std::list<PresentityPresenceInformationListener*> mSubscribers;
};

std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation&);
FlexisipException& operator<<(FlexisipException& ex,const PresentityPresenceInformation&);

} /* namespace flexisip */

#endif /* PRESENCETUPLE_HH_ */
