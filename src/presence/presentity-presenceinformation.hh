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
	PresenceInformationElement(list<pidf::tuple*> tuples,  belle_sip_main_loop_t* mainLoop,  belle_sip_source_t* expirationTimer);
	~PresenceInformationElement();
	time_t getExpitationTime() const;
	/*
	 * update expire from now in second*/
	void setExpires(unsigned int expiration);
	pidf::tuple* getTuple(const string& id) const;
	void addTuple(pidf::tuple*);
	void removeTuple(pidf::tuple*);
	void clearTuples();
private:
	list<pidf::tuple*> mTuples;
	belle_sip_main_loop_t* mBelleSipMainloop;
	belle_sip_source_t* mTimer;
};

class PresentityPresenceInformation {

public:

	class Listener {
		public:
		virtual void onInformationChanged(const PresentityPresenceInformation& presenceInformation)=0;
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



	PresentityPresenceInformation(belle_sip_uri_t* entity,EtagManager& etagManager,belle_sip_main_loop_t *ml);
	virtual ~PresentityPresenceInformation();

	const belle_sip_uri_t* getEntity() const;



private:
	const belle_sip_uri_t* mEntity;
	EtagManager& mEtagManager;
	belle_sip_main_loop_t* mBelleSipMainloop;
	//Tuples ordered by Etag.
	std::map<std::string /*Etag*/,PresenceInformationElement*> mInformationElements;

	// list of subscribers function to be called when a tuple changed
	std::map<belle_sip_uri_t*,Listener*> mSubscribers;
};

std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation&);

} /* namespace flexisip */

#endif /* PRESENCETUPLE_HH_ */
