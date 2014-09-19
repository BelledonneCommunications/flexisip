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

#define ETAG_SIZE 8
using namespace pidf;

namespace flexisip {

PresentityPresenceInformation::PresentityPresenceInformation(belle_sip_uri_t* entity, EtagManager& etagManager,belle_sip_main_loop_t* mainloop)
	:mEntity(entity)
	,mEtagManager(etagManager)
	,mBelleSipMainloop(mainloop){
	belle_sip_object_ref(entity);
	belle_sip_object_ref(mainloop);

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
		informationElement = it->second;
		SLOGD << "Updating presence information element ["<<  std::hex <<  (long)informationElement <<"]  for presentity [" << *this <<"]";
	} else {
		//no etag, check for tuples
		if (tuples == NULL)
			throw FLEXISIP_EXCEPTION << "Cannot create information element for presentity ["<< *this <<"]  without tuple";
		informationElement= new PresenceInformationElement(tuples,mBelleSipMainloop);
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
	return __os << "entity [" << p.getEntity() <<"]";
}

const belle_sip_uri_t* PresentityPresenceInformation::getEntity() const {
	return mEntity;
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
