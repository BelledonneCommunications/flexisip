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
	
}

bool CallContextBase::match(sip_t *sip){
	if (sip->sip_call_id==NULL) return false;
	if (sip->sip_call_id->i_hash==mCallHash){
		return ModuleToolbox::fromMatch(mFrom,sip->sip_from);
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
	mInvCseq=sip->sip_cseq->cs_seq;
	mInvite=msg_copy(msg);
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

void CallContextBase::dump(){
	LOGD("Call id %u",mCallHash);
}

CallContextBase::~CallContextBase(){
	su_home_deinit(&mHome);
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

void  CallStore::removeInactives(){
	list<CallContextBase*>::iterator it;
	list <CallContextBase*>::iterator new_end;
	time_t cur=time(NULL);
	new_end=remove_if(mCalls.begin(),mCalls.end(),bind2nd(mem_fun(&CallContextBase::isInactive),cur));
	mCalls.erase(new_end,mCalls.end());
}

void CallStore::dump(){
	for_each(mCalls.begin(),mCalls.end(),mem_fun(&CallContextBase::dump));
}
