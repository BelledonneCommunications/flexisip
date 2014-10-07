/*
 * PresenceTuple.cc
 *
 *  Created on: 5 juin 2014
 *      Author: jehanmonnier
 */

#include "presentity-presenceinformation.hh"
#include "belle-sip/belle-sip.h"
#include "flexisip-exception.hh"
#include <ostream>
#include <functional>
#include "etag-manager.hh"
#include "application_pidf+xml/pidf+xml.hxx"
#include "application_pidf+xml/pidf+xml-simpl.hxx"

#define ETAG_SIZE 8
using namespace pidf;

namespace flexisip {
	
	PresentityPresenceInformation::PresentityPresenceInformation(const belle_sip_uri_t* entity, EtagManager& etagManager,belle_sip_main_loop_t* mainloop)
	:mEntity((belle_sip_uri_t*)belle_sip_object_clone(BELLE_SIP_OBJECT(entity)))
	,mEtagManager(etagManager)
	,mBelleSipMainloop(mainloop){
		belle_sip_object_ref(mainloop);
		belle_sip_object_ref((void*)mEntity);
		
	}
	
	PresentityPresenceInformation::~PresentityPresenceInformation() {
		for(auto it=mInformationElements.begin();it!=mInformationElements.end();++it) {
			delete it->second;
			it=mInformationElements.erase(it);
		}
		belle_sip_object_unref((void*)mEntity);
		belle_sip_object_unref((void*)mBelleSipMainloop);
		SLOGD <<  "Presence information ["<< std::hex << (long)this << "] deleted";
	}
	static int source_func(std::function<int (unsigned int)>* user_data, unsigned int events) {
		int result = (*user_data)(events);
		delete user_data;
		return result;
	}
	string  PresentityPresenceInformation::putTuples(pidf::presence::tuple_sequence& tuples, int expires) {
		return setOrUpdate(&tuples, NULL, expires);
	}
	string  PresentityPresenceInformation::updateTuples(pidf::presence::tuple_sequence& tuples, string& eTag, int expires) throw (FlexisipException) {
		return setOrUpdate(&tuples, &eTag, expires);
	}
	void PresenceInformationElement::clearTuples() {
		
		for(auto tupIt=mTuples.begin();tupIt!=mTuples.end();++tupIt) {
			delete *tupIt;
			tupIt = mTuples.erase(tupIt);
		}
	}
	string PresentityPresenceInformation::setOrUpdate(pidf::presence::tuple_sequence* tuples, const string* eTag,int expires) throw (FlexisipException) {
		PresenceInformationElement* informationElement=NULL;
		
		//etag ?
		if (eTag && eTag->size()>0) {
			//check if already exist
			auto it = mInformationElements.find(*eTag);
			if (it == mInformationElements.end())
				throw FLEXISIP_EXCEPTION << "Unknown eTag [" << eTag << "] for presentity [" << *this <<"]";
			if (tuples == NULL) {
				//juste a refresh
				informationElement = it->second;
				SLOGD << "Updating presence information element ["<< informationElement <<"]  for presentity [" << *this <<"]";
			} else {
				// remove
				delete it->second;
				mInformationElements.erase(it);
			}
			
			
		} else {
			//no etag, check for tuples
			if (tuples == NULL)
				throw FLEXISIP_EXCEPTION << "Cannot create information element for presentity ["<< *this <<"]  without tuple";
			
		}
		
		if (!informationElement) { //create a new one if needed
			informationElement= new PresenceInformationElement(tuples,mBelleSipMainloop);
			SLOGD << "Creating presence information element ["<< informationElement <<"]  for presentity [" << *this <<"]";
		}
		//generate new etag
		char generatedETag_char[ETAG_SIZE];
		belle_sip_random_token(generatedETag_char,sizeof(generatedETag_char));
		string generatedETag = generatedETag_char;
		
		//update etag for this information element
		informationElement->setEtag(generatedETag);
		
		// cb function to invalidate an unrefreshed etag;
		std::function<int (unsigned int)> *func = new std::function<int (unsigned int)>([this,generatedETag](unsigned int events) {
			//find information element
			this->removeTuplesForEtag(generatedETag);
			mEtagManager.invalidateETag(generatedETag);
			SLOGD << "eTag ["<< generatedETag << "] has expired";
			return BELLE_SIP_STOP;
		});
		// create timer
		belle_sip_source_t* timer = belle_sip_main_loop_create_timeout(mBelleSipMainloop
																	   ,(belle_sip_source_func_t)source_func
																	   , func
																	   , expires*1000
																	   ,"timer for presence Info");
		
		//set expiration timer
		informationElement->setExpiresTimer(timer);
		
		//modify global etag list
		if (eTag && eTag->size()>0) {
			mEtagManager.modifyEtag(*eTag,generatedETag);
			mInformationElements.erase(*eTag);
		}
		else {
			mEtagManager.addEtag(this, generatedETag);
		}
		
		//modify etag list for this presenceInfo
		mInformationElements[generatedETag]= informationElement;
		
		//triger notify on all listeners
		notifyAll();
		
		return generatedETag;
	}
	
	string PresentityPresenceInformation::refreshTuplesForEtag(const string& eTag,int expires) throw (FlexisipException) {
		return setOrUpdate(NULL, &eTag,expires);
	}
	
	void PresentityPresenceInformation::removeTuplesForEtag(const string& eTag) {
		auto it = mInformationElements.find(eTag);
		if (it != mInformationElements.end()) {
			PresenceInformationElement* informationElement = it->second;
			mInformationElements.erase(it);
			delete informationElement;
		} else
			SLOGD << "No tulpes found for etag ["<< eTag << "]";
	}
	
	std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation& p) {
		return __os << "entity [" << p.getEntity() <<"]/"<<&p;
	}
	
	const belle_sip_uri_t* PresentityPresenceInformation::getEntity() const {
		return mEntity;
	}
	
	void PresentityPresenceInformation::addOrUpdateListener( Listener& listener,int expires) {
		
		//search if exist
		string op;
		bool listener_exist = false;
		for (Listener * existing_listener:mSubscribers) {
			if (&listener == existing_listener) {
				listener_exist=true;
				break;
			}
		}
		if (listener_exist) {
			op="Updating";
		} else {
			//not found, adding
			mSubscribers.push_back(&listener);
			op="Adding";
		}

		
		SLOGD << op<<" listener ["<<&listener <<"] on ["<<*this<<"] for ["<<expires<<"] seconds";
		Listener* listener_ptr=&listener;
		// cb function to invalidate an unrefreshed etag;
		std::function<int (unsigned int)> *func = new std::function<int (unsigned int)>([this,listener_ptr](unsigned int events) {
			listener_ptr->onExpired(*this);
			this->removeListener(*listener_ptr);
			SLOGD << "Listener ["<<listener_ptr << "] on ["<<*this<<"] has expired";
			return BELLE_SIP_STOP;
		});
		// create timer
		belle_sip_source_t* timer = belle_sip_main_loop_create_timeout(mBelleSipMainloop
																	   ,(belle_sip_source_func_t)source_func
																	   , func
																	   , expires*1000
																	   ,"timer for presence info listener");
		
		//set expiration timer
		listener.setExpiresTimer(mBelleSipMainloop,timer);

		
		
		/*
		 *rfc 3265
		 * 3.1.6.2. Confirmation of Subscription Creation/Refreshing
		 *
		 * Upon successfully accepting or refreshing a subscription, notifiers
		 * MUST send a NOTIFY message immediately to communicate the current
		 * resource state to the subscriber.
		 */
		listener.onInformationChanged(*this);
		
	}
	void PresentityPresenceInformation::removeListener( Listener& listener) {
		SLOGD << "removing listener ["<<&listener <<"] on ["<<*this<<"]";
		mSubscribers.remove(&listener);
		//			 3.1.4.3. Unsubscribing
		//
		//			 Unsubscribing is handled in the same way as refreshing of a
		//			 subscription, with the "Expires" header set to "0".  Note that a
		//			 successful unsubscription will also trigger a final NOTIFY message.
		listener.onInformationChanged(*this);
		
	}
	
	
	string PresentityPresenceInformation::getPidf() throw (FlexisipException){
		pidf::presence presence;
		char* entity= belle_sip_uri_to_string(getEntity());
		presence.entity(string(entity));
		belle_sip_free(entity);
		
		for (auto element:mInformationElements) {
			for (pidf::tuple* tup :element.second->getTuples()){
				presence.tuple().push_back(tup->_clone());
			}
		}
		pidf::note value;
		namespace_::lang lang;
		value+="No presence information available yet";
		lang.value("en");
		value.lang(lang);
		//value.lang("en");
		if (presence.tuple().size()==0) {
			presence.note().push_back(value);
		}
		stringstream out;
		try {
			
			out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"<<std::endl;
			presence_saggr presence_s;
			
			xml_schema::document_simpl doc_s (presence_s.root_serializer (), presence_s.root_namespace(),presence_s.root_name ());
			doc_s.add_prefix("", presence_s.root_namespace());
			presence_s.pre (presence);
			doc_s.serialize (out, xml_schema::document_simpl::pretty_print);
			presence_s.post ();
	  
		}
		catch (const xml_schema::serializer_exception& e) {
			FLEXISIP_EXCEPTION << "error: " << e.text () << endl;
		}
		return out.str();
	}
	
	void PresentityPresenceInformation::notifyAll() {
			for (Listener* listener:mSubscribers) {
				listener->onInformationChanged(*this);
		}
		SLOGD << *this << " has notified ["<< mSubscribers.size() << " ] listeners";
	}
	PresentityPresenceInformation::Listener::Listener():mTimer(NULL) {
		
	}
	PresentityPresenceInformation::Listener::~Listener() {
		if (mTimer) {
			belle_sip_object_unref(mTimer);
		}
	}
	void PresentityPresenceInformation::Listener::setExpiresTimer(belle_sip_main_loop_t *ml,belle_sip_source_t* timer) {
		if (mTimer) {
			//canceling previous timer
			belle_sip_main_loop_remove_source(ml,mTimer);
			belle_sip_object_unref(mTimer);
		}
		mTimer = timer;
		belle_sip_object_ref(mTimer);
	}
	
	//PresenceInformationElement
	
	PresenceInformationElement::PresenceInformationElement(pidf::presence::tuple_sequence* tuples, belle_sip_main_loop_t* mainLoop):mBelleSipMainloop(mainLoop),mTimer(NULL) {
		for (pidf::presence::tuple_sequence::iterator tupleIt = tuples->begin(); tupleIt!=tuples->end();++tupleIt) {
			SLOGD << "Adding tuple id ["<<tupleIt->id()<<"] to presence info element [" << std::hex <<  (long)this <<"]";
			mTuples.push_back(tuples->detach(tupleIt));
		}
	}
	PresenceInformationElement::~PresenceInformationElement(){
		for (pidf::tuple* tup:mTuples) {
			delete tup;
		}
		belle_sip_main_loop_remove_source(mBelleSipMainloop,mTimer);
		
		SLOGD <<  "Presence information element ["<< std::hex << (long)this << "] deleted";
	}
	void PresenceInformationElement::setExpiresTimer(belle_sip_source_t* timer){
		if (mTimer) {
			//canceling previous timer
			belle_sip_main_loop_remove_source(mBelleSipMainloop,mTimer);
			belle_sip_object_unref(mTimer);
		}
		mTimer = timer;
		belle_sip_object_ref(mTimer);
	}
	pidf::tuple* PresenceInformationElement::getTuple(const string& id) const {
		for (pidf::tuple* tup:mTuples) {
			if (tup->id().compare(id)== 0)
				return tup;
		}
		return NULL;
	}
	const list<pidf::tuple*> PresenceInformationElement::getTuples() const {
		return mTuples;
	}
	void PresenceInformationElement::addTuple(pidf::tuple* tup) {
		mTuples.push_back(tup);
	}
	void PresenceInformationElement::removeTuple(pidf::tuple* tup) {
		mTuples.remove(tup);
	}
	const string& PresenceInformationElement::getEtag() {
		return mEtag;
	}
	void PresenceInformationElement::setEtag(const string& eTag) {
		mEtag=eTag;
	}
	

	
} /* namespace flexisip */
