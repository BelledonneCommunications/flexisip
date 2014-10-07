/*
 * PresenceTuple.hh
 *
 *  Created on: 5 juin 2014
 *      Author: jehanmonnier
 */

#ifndef PRESENCETUPLE_HH_
#define PRESENCETUPLE_HH_

#include <map>
#include "application_pidf+xml/pidf+xml.hxx"
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
	PresenceInformationElement(pidf::presence::tuple_sequence* tuples, belle_sip_main_loop_t* mainLoop);
	~PresenceInformationElement();
	time_t getExpitationTime() const;
	void setExpiresTimer( belle_sip_source_t* timer);
	pidf::tuple* getTuple(const string& id) const;
	const list<pidf::tuple*> getTuples() const;
	void addTuple(pidf::tuple*);
	void removeTuple(pidf::tuple*);
	void clearTuples();
	const string& getEtag();
	void setEtag(const string& eTag);
private:
	list<pidf::tuple*> mTuples;
	belle_sip_main_loop_t* mBelleSipMainloop;
	belle_sip_source_t* mTimer;
	string mEtag;
};
/*
 * Presence Information is the key class representy a presentity. This class can be either created bu a Publish for a presentiry or by a Subscription to a presentity
 
 */
class PresentityPresenceInformation {

public:

	class Listener {
		
	public:
		Listener();
		~Listener();
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

	/*
	 * store tuples a new tupple;
	 * @return new eTag
	 * */
	string  putTuples(pidf::presence::tuple_sequence& tuples, int expires);

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
	string  updateTuples(pidf::presence::tuple_sequence& tuples, string& eTag, int expires) throw (FlexisipException);

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
	void addOrUpdateListener(Listener& listener,int expires);
	/*
	 * remove listener
	 */
	void removeListener(Listener& listener);
	
	
	/*
	 * return the presence information for this entity in a pidf serilized format
	 */
	string getPidf() throw (FlexisipException);
	
	

private:
	/*
	 * tuples may be null
	 */
	string setOrUpdate(pidf::presence::tuple_sequence* tuples, const string* eTag,int expires) throw (FlexisipException);
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
	std::list<Listener*> mSubscribers;
};

std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation&);

} /* namespace flexisip */

#endif /* PRESENCETUPLE_HH_ */
