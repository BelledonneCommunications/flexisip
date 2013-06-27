/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#include "forkcontext.hh"
#include "registrardb.hh"

using namespace ::std;


ForkContextConfig::ForkContextConfig() : mDeliveryTimeout(0),mUrgentTimeout(5),
	mForkLate(false),mForkOneResponse(false), mForkNoGlobalDecline(false),
	mTreatDeclineAsUrgent(false), mRemoveToTag(false){
}

void ForkContext::__timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg){
	(static_cast<ForkContext*>(arg))->onLateTimeout();
}

ForkContext::ForkContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		mListener(listener), mAgent(agent), mEvent(make_shared<RequestSipEvent>(event)), mCfg(cfg), mLateTimer(NULL) {
	mLateTimerExpired=false;
	su_home_init(&mHome);
}

void ForkContext::checkFinished(){
	bool finished=false;
	if (mIncoming==NULL && mOutgoings.size()==0){
		if (mLateTimer){
			finished=mLateTimerExpired;
		}else finished=true;
	}
	if (finished)
		setFinished();
}

void ForkContext::onLateTimeout(){
	LOGD("ForkContext: late timer expired.");
	shared_ptr<ForkContext> me(shared_from_this()); //this is to keep the object alive at least the time of the timer callback.
	//Indeed sofia does not hold a refcount to the ForkContext. During checkFinished() the refcount my drop to zero, but we need to the object
	//to be kept alive until checkFinished() returns.
	mLateTimerExpired=true;
	checkFinished();
}

struct dest_finder{
	dest_finder(const sip_contact_t *ctt) : mCtt(ctt){
		//mUniqueId=Record::extractUniqueId(ctt->m_url);
	}
	bool operator()(const url_t *dest){
		/*
		if (!mUniqueId.empty()){
			string uniqueid=Record::extractUniqueId(dest);
			if (uniqueid==mUniqueId)
				return true;
		}
		*/
		if (url_cmp_all(dest,mCtt->m_url)==0)
			return true;
		return false;
	}
	const sip_contact_t *mCtt;
	string mUniqueId;
};


//this implementation looks for already pending or failed transactions and then rejects handling of a new one that would already been tried.
bool ForkContext::onNewRegister(const sip_contact_t* ctt){
	auto it=find_if(mDestinationUris.begin(),mDestinationUris.end(),dest_finder(ctt));
	if (it!=mDestinationUris.end()){
		LOGD("ForkContext %p: onNewRegister(): destination already handled.",this);
		return false;
	}
	return true;
}


void ForkContext::onNew(const shared_ptr<IncomingTransaction> &transaction) {
	mIncoming = transaction;
	if (mCfg->mForkLate && mLateTimer==NULL){
		/*this timer is for when outgoing transaction all die prematuraly, we still need to wait that late register arrive.*/
		mLateTimer=su_timer_create(su_root_task(mAgent->getRoot()), 0);
		su_timer_set_interval(mLateTimer, &ForkContext::__timer_callback, this, (su_duration_t)mCfg->mDeliveryTimeout* (su_duration_t)1000);
	}
}

void ForkContext::onDestroy(const shared_ptr<IncomingTransaction> &transaction) {
	mIncoming.reset();
	checkFinished();
}

void ForkContext::onNew(const shared_ptr<OutgoingTransaction> &transaction) {
	mOutgoings.push_back(transaction);
	mDestinationUris.push_back(url_hdup(&mHome,transaction->getRequestUri()));
}

void ForkContext::onDestroy(const shared_ptr<OutgoingTransaction> &transaction) {
	mOutgoings.remove(transaction);
	checkFinished();
}


const shared_ptr<RequestSipEvent> &ForkContext::getEvent() {
	return mEvent;
}

ForkContext::~ForkContext() {
	if (mLateTimer)
		su_timer_destroy(mLateTimer);
	su_home_deinit(&mHome);
}

void ForkContext::setFinished(){
	if (mLateTimer){
		su_timer_destroy(mLateTimer);
		mLateTimer=NULL;
	}
	//force reference to be loosed immediately, to avoid circular dependencies.
	mEvent.reset();
	mIncoming.reset();
	mOutgoings.clear();
	mListener->onForkContextFinished(shared_from_this());
}

