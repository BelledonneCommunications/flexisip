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
}
static int source_func(std::function<int (unsigned int)>* user_data, unsigned int events) {
	int result = (*user_data)(events);
	delete user_data;
	return result;
}
string  PresentityPresenceInformation::putTuples(pidf::presence::tuple_sequence& tuples, int expires) {
	char generatedETag_char[ETAG_SIZE];
	belle_sip_random_token(generatedETag_char,sizeof(generatedETag_char));
	 string generatedETag = generatedETag_char;
	//create initial tuple list
	list<pidf::tuple*> tupleList;
	for (pidf::presence::tuple_sequence::iterator tupleIt = tuples.begin(); tupleIt!=tuples.end();++tupleIt) {
		SLOGD << "Adding tuple id ["<<tupleIt->id()<<"] for etag [" << generatedETag <<"]";
		tupleList.push_back(tuples.detach(tupleIt));
	}
	// cb function to invalidate an unrefreshed etag;
	std::function<int (unsigned int)> *func = new std::function<int (unsigned int)>([this,generatedETag](unsigned int events) {
		//find information element
		auto it = mInformationElements.find(generatedETag);
		if (it != mInformationElements.end()) {
			delete it->second;
			mInformationElements.erase(it);
		}
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


	// put presence info into etag list
	mInformationElements[generatedETag]= new PresenceInformationElement(tupleList,mBelleSipMainloop,timer);
	mEtagManager.addEtag(this, generatedETag);

	return generatedETag;
}
string  PresentityPresenceInformation::updateTuples(pidf::presence::tuple_sequence& tuples, string& eTag, int expires) throw (FlexisipException) {
	//check if already exist
	auto it = mInformationElements.find(eTag);
	if (it == mInformationElements.end())
		throw FLEXISIP_EXCEPTION << "Unknown eTag [" << eTag << "] for presentity [" << *this <<"]";

	PresenceInformationElement* informationElement = it->second;
	informationElement->clearTuples();
	//for each tuple to update
	for (pidf::presence::tuple_sequence::iterator newTupleIt = tuples.begin(); newTupleIt!=tuples.end();++newTupleIt) {
		pidf::tuple* tuple=NULL;
/*		if ((tuple=informationElement->getTuple(newTupleIt->id()))) {
			SLOGD << "Updating tuple id ["<<newTupleIt->id()<<"]";
			informationElement->removeTuple(tuple);
			delete tuple;
		} else {
			SLOGD << "Adding tuple id ["<<newTupleIt->id()<<"]";

		}*/
		SLOGD << "Adding/Updating tuple id ["<<newTupleIt->id()<<"] for etag [" << eTag <<"]";
		informationElement->addTuple(tuples.detach(newTupleIt));

	}
	return refreshTuplesForEtag( eTag,expires);

}
void PresenceInformationElement::clearTuples() {
	for(auto tupIt=mTuples.begin();tupIt!=mTuples.end();++tupIt) {
		delete *tupIt;
		tupIt = mTuples.erase(tupIt);
	}
}
string PresentityPresenceInformation::refreshTuplesForEtag(const string& eTag,int expires) throw (FlexisipException) {
	//check if already exist
	auto it = mInformationElements.find(eTag);
	if (it == mInformationElements.end())
		throw FLEXISIP_EXCEPTION << "Unknown eTag [" << eTag << "] for presentity [" << *this <<"]";
	PresenceInformationElement* informationElement = it->second;

	//update expiration timer
	informationElement->setExpires(expires);
	//generate new etag
	char generatedETag_char[ETAG_SIZE];
	belle_sip_random_token(generatedETag_char,sizeof(generatedETag_char));
	string generatedETag = generatedETag_char;
	//modify global etag list
	mEtagManager.modifyEtag(eTag,generatedETag);
	//modify etag list for this presenceInfo
	mInformationElements[generatedETag]= informationElement;
	return generatedETag;
}

void PresentityPresenceInformation::removeTuplesForEtag(const string& eTag) {
	auto it = mInformationElements.find(eTag);
	if (it != mInformationElements.end()) {
		PresenceInformationElement* informationElement = it->second;
		mInformationElements.erase(it);
		delete informationElement;
	}
}

std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation& p) {
	return __os << "entity [" << p.getEntity() <<"]";
}

const belle_sip_uri_t* PresentityPresenceInformation::getEntity() const {
	return mEntity;
}


//PresenceInformationElement
PresenceInformationElement::PresenceInformationElement(list<pidf::tuple*> tuples
															, belle_sip_main_loop_t* mainLoop
															, belle_sip_source_t* expirationTimer):mBelleSipMainloop(mainLoop), mTimer(expirationTimer){
	mTuples.assign(tuples.begin(),tuples.end());
}
PresenceInformationElement::~PresenceInformationElement(){
	for (pidf::tuple* tup:mTuples) {
		delete tup;
	}
	belle_sip_main_loop_remove_source(mBelleSipMainloop,mTimer);
}
void PresenceInformationElement::setExpires(unsigned int expiration){
	belle_sip_source_set_timeout(mTimer,expiration);
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

} /* namespace flexisip */
