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
	mCallHash=sip->sip_call_id->i_hash;
	mInvCseq=sip->sip_cseq->cs_seq;
}

bool CallContextBase::match(sip_t *sip){
	return sip->sip_call_id->i_hash==mCallHash;
}

bool CallContextBase::isNewInvite (sip_t *invite){
	return invite->sip_cseq->cs_seq!=mInvCseq;
}

bool CallContextBase::isNew200Ok(sip_t *sip){
	return sip->sip_cseq->cs_seq!=mInvCseq;
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
