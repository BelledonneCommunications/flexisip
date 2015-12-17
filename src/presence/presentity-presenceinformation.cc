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
#include "flexisip-exception.hh"
#include <ostream>
#include <functional>
#include "etag-manager.hh"
#include "pidf+xml.hxx"

#define ETAG_SIZE 8
using namespace pidf;

namespace flexisip {
	
FlexisipException& operator<< (FlexisipException& e, const xml_schema::Exception& val) {
	stringstream e_out;
	e_out << val;
	e<<e_out.str();
	return e;
}
	
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
		SLOGD <<  "Presence information ["<< this << "] deleted";
	}
	static int source_func(std::function<int (unsigned int)>* user_data, unsigned int events) {
		int result = (*user_data)(events);
		delete user_data;
		return result;
	}
	string  PresentityPresenceInformation::putTuples(pidf::Presence::TupleSequence& tuples, pidf::Presence::AnySequence& extensions, int expires) {
		return setOrUpdate(&tuples, &extensions, NULL, expires);
	}
	string  PresentityPresenceInformation::updateTuples(pidf::Presence::TupleSequence& tuples, pidf::Presence::AnySequence& extensions, string& eTag, int expires) throw (FlexisipException) {
		return setOrUpdate(&tuples, &extensions, &eTag, expires);
	}
	void PresenceInformationElement::clearTuples() {
		
		for(auto tupIt=mTuples.begin();tupIt!=mTuples.end();++tupIt) {
			tupIt = mTuples.erase(tupIt);
		}
	}
	string PresentityPresenceInformation::setOrUpdate(	pidf::Presence::TupleSequence* tuples
													  , pidf::Presence::AnySequence* extensions
													  , const string* eTag,int expires) throw (FlexisipException) {
		PresenceInformationElement* informationElement=NULL;
		
		//etag ?
		if (eTag && eTag->size()>0) {
			//check if already exist
			auto it = mInformationElements.find(*eTag);
			if (it == mInformationElements.end())
				throw FLEXISIP_EXCEPTION << "Unknown eTag [" << *eTag << "] for presentity [" << *this <<"]";
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
			informationElement= new PresenceInformationElement(tuples,extensions, mBelleSipMainloop);
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
																	   ,(belle_sip_source_func_t)belle_sip_source_cpp_func
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
			mEtagManager.addEtag(shared_from_this(), generatedETag);
		}
		
		//modify etag list for this presenceInfo
		mInformationElements[generatedETag]= informationElement;
		
		//triger notify on all listeners
		notifyAll();
		SLOGD << "Etag [" << generatedETag << "] associated to Presentity ["<< *this <<"]";
		return generatedETag;
	}
	
	string PresentityPresenceInformation::refreshTuplesForEtag(const string& eTag,int expires) throw (FlexisipException) {
		return setOrUpdate(NULL, NULL, &eTag,expires);
	}
	
	void PresentityPresenceInformation::removeTuplesForEtag(const string& eTag) {
		auto it = mInformationElements.find(eTag);
		if (it != mInformationElements.end()) {
			PresenceInformationElement* informationElement = it->second;
			mInformationElements.erase(it);
			delete informationElement;
			notifyAll(); // Removing an event state change global state, so it should be notified
		} else
			SLOGD << "No tulpes found for etag ["<< eTag << "]";
	}
	
	FlexisipException& operator<<(FlexisipException& ex,const PresentityPresenceInformation& p) {
		return ex << "entity [" << p.getEntity() <<"]/"<<&p;
	}
	std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation& p) {
		return __os << "entity [" << p.getEntity() <<"]/"<<&p;
	}
	
	const belle_sip_uri_t* PresentityPresenceInformation::getEntity() const {
		return mEntity;
	}
	
	void PresentityPresenceInformation::addOrUpdateListener(shared_ptr<PresentityPresenceInformationListener> listener,int expires) {
		
		//search if exist
		string op;
		bool listener_exist = false;
		for (const shared_ptr<PresentityPresenceInformationListener> existing_listener:mSubscribers) {
			if (listener == existing_listener) {
				listener_exist=true;
				break;
			}
		}
		if (listener_exist) {
			op="Updating";
		} else {
			//not found, adding
			mSubscribers.push_back(listener);
			op="Adding";
		}

		
		SLOGD << op<<" listener ["<<listener.get() <<"] on ["<<*this<<"] for ["<<expires<<"] seconds";
		//PresentityPresenceInformationListener* listener_ptr=listener.get();
		// cb function to invalidate an unrefreshed etag;
		std::function<int (unsigned int)> *func = new std::function<int (unsigned int)>([this,listener/*_ptr*/](unsigned int events) {
			listener->onExpired(*this);
			this->removeListener(listener);
			SLOGD << "Listener ["<<listener.get() << "] on ["<<*this<<"] has expired";
			return BELLE_SIP_STOP;
		});
		// create timer
		belle_sip_source_t* timer = belle_sip_main_loop_create_timeout(mBelleSipMainloop
																	   ,(belle_sip_source_func_t)source_func
																	   , func
																	   , expires*1000
																	   ,"timer for presence info listener");
		
		//set expiration timer
		listener->setExpiresTimer(mBelleSipMainloop,timer);

		
		
		/*
		 *rfc 3265
		 * 3.1.6.2. Confirmation of Subscription Creation/Refreshing
		 *
		 * Upon successfully accepting or refreshing a subscription, notifiers
		 * MUST send a NOTIFY message immediately to communicate the current
		 * resource state to the subscriber.
		 */
		listener->onInformationChanged(*this);
		
	}
	void PresentityPresenceInformation::removeListener(shared_ptr<PresentityPresenceInformationListener> listener) {
		SLOGD << "removing listener ["<<listener.get()<<"] on ["<<*this<<"]";
		//1 cancel expiration time
		listener->setExpiresTimer(mBelleSipMainloop,NULL);
		//2 remove listener
		mSubscribers.remove(listener);
		//			 3.1.4.3. Unsubscribing
		//
		//			 Unsubscribing is handled in the same way as refreshing of a
		//			 subscription, with the "Expires" header set to "0".  Note that a
		//			 successful unsubscription will also trigger a final NOTIFY message.
		listener->onInformationChanged(*this);
		
	}
	
	bool PresentityPresenceInformation::isKnown() {
		return mInformationElements.size() > 0;
	}
	string PresentityPresenceInformation::getPidf() throw (FlexisipException){
		stringstream out;
		try {
			char* entity= belle_sip_uri_to_string(getEntity());
			pidf::Presence presence((string(entity)));
			belle_sip_free(entity);
			list<string> tupleList;
			
			for (auto element:mInformationElements) {
				//copy pidf
				for (const unique_ptr<pidf::Tuple>& tup :element.second->getTuples()){
					//check for multiple tupple id, may happend with buggy presence publisher
					if (find(tupleList.begin(), tupleList.end(),tup.get()->getId()) == tupleList.end()) {
						presence.getTuple().push_back(*tup->_clone());
						tupleList.push_back(tup.get()->getId());
					} else {
						SLOGW << "Already existing tuple id [" << tup.get()->getId() <<" for ["<< *this<< "], skipping";
					}
				}
				//copy extensions
				for( auto extension:element.second->getExtensions()) {
					presence.getAny().push_back(dynamic_cast<xercesc::DOMElement*>(presence.getDomDocument().importNode(extension,true))); // might be optimized
				}
			}
			pidf::Note value;
			namespace_::Lang lang("en");
			value+="No presence information available yet";
			value.setLang(lang);
			//value.lang("en");
			if (presence.getTuple().size()==0) {
				presence.getNote().push_back(value);
			}
			
			// Serialize the object model to XML.
			//
			xml_schema::NamespaceInfomap map;
			map[""].name = "urn:ietf:params:xml:ns:pidf";
			
			serializePresence (out, presence, map);
			
		}
		catch (const xml_schema::Exception& e) {
			throw FLEXISIP_EXCEPTION << "error: " << e ;
		}
		catch (exception& e) {
			throw FLEXISIP_EXCEPTION << "Cannot get pidf for for ["<< *this<< "]error [" << e.what() <<"]" ;
		}
		
		return out.str();
	}
	
	void PresentityPresenceInformation::notifyAll() {
			for (shared_ptr<PresentityPresenceInformationListener> listener:mSubscribers) {
				listener->onInformationChanged(*this);
		}
		SLOGD << *this << " has notified ["<< mSubscribers.size() << " ] listeners";
	}
	PresentityPresenceInformationListener::PresentityPresenceInformationListener():mTimer(NULL) {
		
	}
	PresentityPresenceInformationListener::~PresentityPresenceInformationListener() {
		if (mTimer) {
			belle_sip_object_unref(mTimer);
		}
	}
	void PresentityPresenceInformationListener::setExpiresTimer(belle_sip_main_loop_t *ml,belle_sip_source_t* timer) {
		if (mTimer) {
			//canceling previous timer
			belle_sip_main_loop_remove_source(ml,mTimer);
			belle_sip_object_unref(mTimer);
		}
		mTimer = timer;
		if (mTimer) belle_sip_object_ref(mTimer);
	}
	
	//PresenceInformationElement
	
	PresenceInformationElement::PresenceInformationElement(	 pidf::Presence::TupleSequence* tuples
														   , pidf::Presence::AnySequence* extensions
														   , belle_sip_main_loop_t* mainLoop)
		:mDomDocument(::xsd::cxx::xml::dom::create_document< char > ())
		,mBelleSipMainloop(mainLoop)
		,mTimer(NULL) {
		
		for (pidf::Presence::TupleSequence::iterator tupleIt = tuples->begin(); tupleIt!=tuples->end();) {
			SLOGD << "Adding tuple id ["<<tupleIt->getId()<<"] to presence info element [" << this <<"]";
			std::unique_ptr<Tuple> r;
			tupleIt=tuples->detach(tupleIt, r);
			mTuples.push_back(std::unique_ptr<Tuple>(r.release()));
		}
		
		for (pidf::Presence::AnySequence::iterator domElement = extensions->begin(); domElement!=extensions->end();domElement++) {
			SLOGD << "Adding extension element  ["<<xercesc::XMLString::transcode( domElement->getNodeName())<<"] to presence info element [" << this <<"]";
			mExtensions.push_back(dynamic_cast<xercesc::DOMElement*>(mDomDocument->importNode(&*domElement,true)));
		}
		
		
	}
	PresenceInformationElement::~PresenceInformationElement(){
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
	const std::unique_ptr<pidf::Tuple>& PresenceInformationElement::getTuple(const string& id) const {
		for (const std::unique_ptr<Tuple>& tup:mTuples) {
			if (tup->getId().compare(id)== 0)
				return tup;
		}
		throw FLEXISIP_EXCEPTION << "No tuple found for id [" <<id << "]";
	}
	const list<std::unique_ptr<pidf::Tuple>>& PresenceInformationElement::getTuples() const {
		return mTuples;
	}
	const list<xercesc::DOMElement*>  PresenceInformationElement::getExtensions() const {
		return mExtensions;
	}
/*	void PresenceInformationElement::addTuple(pidf::Tuple* tup) {
		mTuples.push_back(tup);
	}
	void PresenceInformationElement::removeTuple(pidf::Tuple* tup) {
		mTuples.remove(tup);
	}*/
	const string& PresenceInformationElement::getEtag() {
		return mEtag;
	}
	void PresenceInformationElement::setEtag(const string& eTag) {
		mEtag=eTag;
	}
	

	
} /* namespace flexisip */
