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

using namespace ::std;


ForkContextConfig::ForkContextConfig() : mDeliveryTimeout(0),mForkLate(false),mForkOneResponse(false), mForkNoGlobalDecline(false){
}

void ForkContext::__timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg){
	(static_cast<ForkContext*>(arg))->onLateTimeout();
}

ForkContext::ForkContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener) :
		mListener(listener), mAgent(agent), mEvent(make_shared<RequestSipEvent>(event)), mCfg(cfg), mLateTimer(NULL) {
	mLateTimerExpired=false;
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
	mLateTimerExpired=true;
	checkFinished();
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

