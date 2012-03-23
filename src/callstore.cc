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
	mAck=NULL;
	mCallerTag=sip->sip_from->a_tag;
	mViaCount = 0;
	sip_via_t *via;
	for(via = sip->sip_via; via != NULL; via = via->v_next) 
		++mViaCount;
	via=sip->sip_via;
	if (via && via->v_branch){
		mBranch=via->v_branch;
	}
}

bool CallContextBase::match(Agent *ag, sip_t *sip, bool stateful){
	if (sip->sip_call_id==NULL) return false;
	if (sip->sip_from->a_tag==NULL) return false;
	
	if (sip->sip_call_id->i_hash==mCallHash){
		if (sip->sip_request==NULL && (sip->sip_status->st_status>100 && sip->sip_status->st_status<300) ){
			if (mCalleeTag.empty() && strcmp(mCallerTag.c_str(),sip->sip_from->a_tag)==0){
				/*not yet established dialog*/
				//check the via branch to know if that response can correspond to the original INVITE
				//and possibly establish the dialog.
				sip_via_t *respvia=ag->getNextVia(sip);
				if (respvia && respvia->v_branch){
					if (strcmp(respvia->v_branch,mBranch.c_str())==0){
						LOGD("Found CallContext matching response");
						return true;
					}
				}
			}
		}
		/*otherwise the to tag must be set (dialog established)*/
		if (sip->sip_to && sip->sip_to->a_tag){
			//note: in case of re-INVITE, from and to tags might be inverted with mCallerTag and mCalleeTag
			if ( (strcmp(mCallerTag.c_str(),sip->sip_from->a_tag)==0 && strcmp(mCalleeTag.c_str(),sip->sip_to->a_tag)==0) ||
			   (strcmp(mCallerTag.c_str(),sip->sip_to->a_tag)==0 && strcmp(mCalleeTag.c_str(),sip->sip_from->a_tag)==0)){
				LOGD("Found exact dialog");
				return true;
			}
		}
		if(stateful)
			return true;
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
	if(mInvite != NULL){
		msg_destroy(mInvite);
	}
	mInvite=msg_copy(msg);
}

void CallContextBase::storeNewAck(msg_t *msg){
	sip_t *sip=(sip_t*)msg_object(msg);
	//serialize the message before copying it otherwise we might miss some content
	msg_serialize(msg,(msg_pub_t*)sip);
	mAckCseq=sip->sip_cseq->cs_seq;
	if(mAck != NULL){
		msg_destroy(mAck);
	}
	mAck=msg_copy(msg);
}

bool CallContextBase::isNewAck(sip_t *ack){
	return ack->sip_cseq->cs_seq!=mAckCseq;
}

void CallContextBase::storeNewResponse(msg_t *msg){
	sip_t *sip=(sip_t*)msg_object(msg);
	//serialize the message before copying it otherwise we might miss some content
	msg_serialize(msg,(msg_pub_t*)sip);
	if(mResponse != NULL){
		msg_destroy(mResponse);
	}
	mResponse=msg_copy(msg);
	mResCseq=sip->sip_cseq->cs_seq;
	if (mCalleeTag.empty()){
		if (sip->sip_to && sip->sip_to->a_tag){
			LOGD("Response establishes a dialog or early dialog.");
			mCalleeTag=sip->sip_to->a_tag;
		}
	}
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
	if(mInvite != NULL){
		msg_destroy(mInvite);
	}
	if(mResponse != NULL){
		msg_destroy(mResponse);
	}
	if(mAck != NULL){
		msg_destroy(mAck);
	}
}

CallStore::CallStore() : mCountCalls(NULL),mCountCallsFinished(NULL){
}

CallStore::~CallStore(){
}

void CallStore::store(const shared_ptr<CallContextBase> &ctx){
	if (mCountCalls) ++(*mCountCalls);
	mCalls.push_back(ctx);
}

shared_ptr<CallContextBase> CallStore::find(Agent *ag, sip_t *sip, bool stateful){
	for(auto it=mCalls.begin();it!=mCalls.end();++it){
		if ((*it)->match(ag,sip, stateful))
		    return *it;
	}
	return shared_ptr<CallContextBase>();
}

void CallStore::remove(const shared_ptr<CallContextBase> &ctx){
	if (mCountCallsFinished) ++(*mCountCallsFinished);
	mCalls.remove(ctx);
}

void CallStore::removeAndDeleteInactives(){
	time_t cur=time(NULL);
	for(auto it=mCalls.begin();it!=mCalls.end();){
		if ((*it)->isInactive (cur)){
			if (mCountCallsFinished) ++(*mCountCallsFinished);
			it=mCalls.erase(it);
		}else ++it;
	}
}

void CallStore::dump(){
	for_each(mCalls.begin(),mCalls.end(),bind(&CallContextBase::dump, placeholders::_1));
}
