/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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


#include <algorithm>
#include <functional>

#include "callstore.hh"

using namespace::std;

CallContextBase::CallContextBase(sip_t *sip){
	su_home_init(&mHome);
	mFrom=sip_from_dup(&mHome,sip->sip_from);
	mCallHash=sip->sip_call_id->i_hash;
	mInvCseq=sip->sip_cseq->cs_seq;
	mResCseq=(uint32_t)-1;
	mInvite=NULL;
	mResponse=NULL;
	mTag1=sip->sip_from->a_tag;
}

bool CallContextBase::match(sip_t *sip){
	if (sip->sip_call_id==NULL) return false;
	if (sip->sip_from->a_tag==NULL) return false;
	
	if (sip->sip_call_id->i_hash==mCallHash){
		if (sip->sip_request==NULL && (sip->sip_status->st_status>100 && sip->sip_status->st_status<300) ){
			/*this is a response, we might need to update the second tag*/
			if (strcmp(mTag1.c_str(),sip->sip_from->a_tag)==0 && mTag2.size()==0){
				if (sip->sip_to->a_tag){
					LOGD("Found early dialog, now established");
					mTag2=sip->sip_to->a_tag;
				}
				return true;
			}
		}
		if (sip->sip_to->a_tag==NULL && strcmp(mTag1.c_str(),sip->sip_from->a_tag)==0){
			LOGD("Found dialog for early request");
			return true;
		}
		if ((strcmp(mTag1.c_str(),sip->sip_from->a_tag)==0 && sip->sip_to->a_tag && strcmp(mTag2.c_str(),sip->sip_to->a_tag)==0) ||
		   ( sip->sip_to->a_tag && strcmp(mTag1.c_str(),sip->sip_to->a_tag)==0 && strcmp(mTag2.c_str(),sip->sip_from->a_tag)==0)){
			LOGD("Found exact dialog");
			return true;
		}
	}
	return false;
}

bool CallContextBase::isNewInvite (sip_t *invite){
	return invite->sip_cseq->cs_seq!=mInvCseq;
}

bool CallContextBase::isNewEarlyMedia(sip_t *sip){
	if (mResponse){
		sip_t *resp=(sip_t*)msg_object(mResponse);
		return resp->sip_cseq->cs_seq!=sip->sip_cseq->cs_seq;
	}
	return true;
}

bool CallContextBase::isNew200Ok(sip_t *sip){
	if (mResponse){
		sip_t *resp=(sip_t*)msg_object(mResponse);
		return resp->sip_status->st_status!=200 ||
		    resp->sip_cseq->cs_seq!=sip->sip_cseq->cs_seq;
	}
	return true;
}

void CallContextBase::storeNewInvite(msg_t *msg){
	sip_t *sip=(sip_t*)msg_object(msg);
	//serialize the message before copying it otherwise we might miss some content
	msg_serialize(msg,(msg_pub_t*)sip);
	mInvCseq=sip->sip_cseq->cs_seq;
	mInvite=msg_copy(msg);
}

void CallContextBase::storeNewAck(msg_t *msg){
	sip_t *sip=(sip_t*)msg_object(msg);
	//serialize the message before copying it otherwise we might miss some content
	msg_serialize(msg,(msg_pub_t*)sip);
	mAckCseq=sip->sip_cseq->cs_seq;
	mAck=msg_copy(msg);
}

bool CallContextBase::isNewAck(sip_t *ack){
	return ack->sip_cseq->cs_seq!=mAckCseq;
}

void CallContextBase::storeNewResponse(msg_t *msg){
	sip_t *sip=(sip_t*)msg_object(msg);
	mResponse=msg_copy(msg);
	mResCseq=sip->sip_cseq->cs_seq;
}

msg_t *CallContextBase::getLastForwardedInvite()const{
	return mInvite;
}

msg_t *CallContextBase::getLastForwaredResponse()const{
	return mResponse;
}

msg_t *CallContextBase::getLastForwardedAck()const{
	return mAck;
}

void CallContextBase::dump(){
	LOGD("Call id %u",mCallHash);
}

CallContextBase::~CallContextBase(){
	su_home_deinit(&mHome);
	LOGD("CallContext %p with id %u destroyed.",this,mCallHash);
}

CallStore::CallStore(){
}

void CallStore::store(CallContextBase *ctx){
	mCalls.push_back(ctx);
}

CallContextBase *CallStore::find(sip_t *sip){
	list<CallContextBase*>::iterator it;
	it=find_if(mCalls.begin(),mCalls.end(),bind2nd(mem_fun(&CallContextBase::match),sip));
	if (it!=mCalls.end())
		return *it;
	return NULL;
}

void CallStore::remove(CallContextBase *ctx){
	mCalls.remove(ctx);
}

void CallStore::removeAndDeleteInactives(){
	list<CallContextBase*>::iterator it;
	time_t cur=time(NULL);
	for(it=mCalls.begin();it!=mCalls.end();){
		if ((*it)->isInactive (cur)){
			delete *it;
			it=mCalls.erase(it);
		}else ++it;
	}
}

void CallStore::dump(){
	for_each(mCalls.begin(),mCalls.end(),mem_fun(&CallContextBase::dump));
}
