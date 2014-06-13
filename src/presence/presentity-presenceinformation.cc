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

using namespace pidf;

namespace flexisip {

PresentityPresenceInformation::PresentityPresenceInformation(belle_sip_uri_t* entity, EtagManager& etagManager,belle_sip_main_loop_t* mainloop)
	:mEntity(entity)
	,mEtagManager(etagManager)
	,mBelleSipMainloop(mainloop){
	belle_sip_object_ref((void*)mEntity);
	belle_sip_object_ref((void*)mBelleSipMainloop);

}

PresentityPresenceInformation::~PresentityPresenceInformation() {
	belle_sip_object_unref((void*)mEntity);
	belle_sip_object_unref((void*)mBelleSipMainloop);
}
static int source_func(std::function<int (unsigned int)> user_data, unsigned int events) {
	return user_data(events);
}
string  PresentityPresenceInformation::putTuples(pidf::presence::tuple_sequence& tuples, int expires) {
	char generatedETag[32];
	belle_sip_random_token(generatedETag,sizeof(generatedETag));
	//create initial tuple list
	list<pidf::tuple*> tupleList;
	for (pidf::presence::tuple_sequence::iterator tupleIt = tuples.begin(); tupleIt!=tuples.end();++tupleIt) {
		tupleList.push_back(tuples.detach(tupleIt));
	}
	// cb function to invalidate an unrefreshed etag;
	std::function<int (unsigned int)> func = [this,generatedETag](unsigned int events) {
		//find information element
		auto it = mInformationElements.find(generatedETag);
		if (it != mInformationElements.end()) {
			mInformationElements.erase(it);
			delete it->second;
		}
		mEtagManager.invalidateETag(generatedETag);
		SLOGD << "eTag ["<< generatedETag << "] has expired";
		return BELLE_SIP_STOP;
	};
	// create timer
	belle_sip_source_t* timer = belle_sip_main_loop_create_timeout(mBelleSipMainloop
								,(belle_sip_source_func_t)source_func
								, &func
								, expires*1000
								,"timer for presence Info");


	// put presence info into etag list
	mInformationElements[generatedETag]= new PresenceInformationElement(tupleList,timer);

	return generatedETag;
}
string  PresentityPresenceInformation::updateTuples(pidf::presence::tuple_sequence& tuples, string eTag, int expires) throw (FlexisipException) {
	//check if already exist
	auto it = mInformationElements.find(eTag);
	if (it == mInformationElements.end())
		throw FLEXISIP_EXCEPTION << "Unknown eTag [" << eTag << "] for presentity [" << *this ;

	PresenceInformationElement* informationElement = it->second;
	//for each tuple to update
	for (pidf::presence::tuple_sequence::iterator newTupleIt = tuples.begin(); newTupleIt!=tuples.end();++newTupleIt) {
		pidf::tuple* tuple=NULL;
		if ((tuple=informationElement->getTuple(newTupleIt->id()))) {
			SLOGD << "Updating tuple id ["<<newTupleIt->id()<<"]";
			informationElement->removeTuple(tuple);
			delete tuple;
		} else {
			SLOGD << "Adding tuple id ["<<newTupleIt->id()<<"]";

		}
		informationElement->addTuple(tuples.detach(newTupleIt));

	}
	//update expiration timer
	informationElement->setExpires(expires);
	//generate new etag
	char generatedETag[32];
	belle_sip_random_token(generatedETag,sizeof(generatedETag));
	//modify global etag list
	mEtagManager.modifyEtag(eTag,generatedETag);
	//modify etag list for this presenceInfo
	mInformationElements[generatedETag]= informationElement;
	return generatedETag;

}

std::ostream& operator<<(std::ostream& __os,const PresentityPresenceInformation& p) {
	return __os << "entity [" << p.getEntity() <<"]";
}
} /* namespace flexisip */
