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

#include "forkcallcontext.hh"
#include "common.hh"
#include <algorithm>
#include <sofia-sip/sip_status.h>

using namespace std;

template <typename T> static bool contains(const list<T> &l, T value) {
	return find(l.cbegin(), l.cend(), value) != l.cend();
}

ForkCallContext::ForkCallContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event,
								 shared_ptr<ForkContextConfig> cfg, ForkContextListener *listener)
	: ForkContext(agent, event, cfg, listener), mShortTimer(NULL), mPushTimer(NULL), mCancelled(false) {
	LOGD("New ForkCallContext %p", this);
	mLog = event->getEventLog<CallLog>();
	mActivePushes = 0;
}

ForkCallContext::~ForkCallContext() {
	LOGD("Destroy ForkCallContext %p", this);
	if (mShortTimer) {
		su_timer_destroy(mShortTimer);
		mShortTimer = NULL;
	}
	if (mPushTimer) {
		su_timer_destroy(mPushTimer);
		mPushTimer = NULL;
	}
}

void ForkCallContext::onCancel(const std::shared_ptr<RequestSipEvent> &ev) {
	mLog->setCancelled();
	mLog->setCompleted();
	mCancelled = true;
	cancelOthers(shared_ptr<BranchInfo>(), ev->getSip());
}

void ForkCallContext::cancelOthers(const shared_ptr<BranchInfo> &br, sip_t *received_cancel) {
	list<shared_ptr<BranchInfo>> branches = getBranches();
	for (auto it = branches.begin(); it != branches.end(); ++it) {
		shared_ptr<BranchInfo> brit = *it;
		if (brit != br) {
			shared_ptr<OutgoingTransaction> tr = brit->mTransaction;
			if (brit->getStatus() < 200 && tr) {
				if(received_cancel && received_cancel->sip_reason) {
					sip_reason_t *reason = sip_reason_dup(tr->getHome(), received_cancel->sip_reason);
					tr->cancelWithReason(reason);
				} else {
					tr->cancel();
				}
			}
			removeBranch(brit);
		}
	}
}

void ForkCallContext::cancelOthersWithStatus(const shared_ptr<BranchInfo> &br, FlexisipForkStatus status) {
	list<shared_ptr<BranchInfo>> branches = getBranches();
	for (auto it = branches.begin(); it != branches.end(); ++it) {
		shared_ptr<BranchInfo> brit = *it;
		if (brit != br) {
			shared_ptr<OutgoingTransaction> tr = brit->mTransaction;
			if (brit->getStatus() < 200 && tr)
				if(status == FlexisipForkAcceptedElsewhere) {
					sip_reason_t* reason = sip_reason_make(tr->getHome(), "SIP;cause=200;text=\"Call completed elsewhere\"");
					tr->cancelWithReason(reason);
				} else if (status == FlexisipForkDeclineElsewhere) {
					sip_reason_t* reason = sip_reason_make(tr->getHome(), "SIP;cause=600;text=\"Busy Everywhere\"");
					tr->cancelWithReason(reason);
				} else {
					tr->cancel();
				}
			removeBranch(brit);
		}
	}
}

const int ForkCallContext::sUrgentCodesWithout603[] = {401, 407, 415, 420, 484, 488, 606, 0};

const int *ForkCallContext::getUrgentCodes() {
	if (mCfg->mTreatAllErrorsAsUrgent)
		return ForkContext::sAllCodesUrgent;
	if (mCfg->mTreatDeclineAsUrgent)
		return ForkContext::sUrgentCodes;
	return sUrgentCodesWithout603;
}

void ForkCallContext::onResponse(const shared_ptr<BranchInfo> &br, const shared_ptr<ResponseSipEvent> &event) {
	const shared_ptr<MsgSip> &ms = event->getMsgSip();
	sip_t *sip = ms->getSip();
	int code = sip->sip_status->st_status;

	if (code >= 300) {
		/*in fork-late mode, we must not consider that 503 and 408 resonse codes (which are send by sofia in case of i/o
		 * error or timeouts) are branches that are answered)
		 * Instead we must wait for the duration of the fork for new registers*/
		if (allBranchesAnswered(mCfg->mForkLate)) {
			shared_ptr<BranchInfo> best = findBestBranch(getUrgentCodes(), mCfg->mForkLate);
			if (best)
				logResponse(forwardResponse(best));
			return;
		}
		if (isUrgent(code, getUrgentCodes()) && mShortTimer == NULL) {
			mShortTimer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
			su_timer_set_interval(mShortTimer, &ForkCallContext::sOnShortTimer, this,
								  (su_duration_t)mCfg->mUrgentTimeout * 1000);
			return;
		}
		if (code >= 600) {
			/*6xx response are normally treated as global faillures */
			if (!mCfg->mForkNoGlobalDecline) {
				logResponse(forwardResponse(br));
				cancelOthersWithStatus(br, FlexisipForkDeclineElsewhere);
			}
		}
	} else if (code >= 200) {
		logResponse(forwardResponse(br));
		cancelOthersWithStatus(br, FlexisipForkAcceptedElsewhere);
	} else if (code >= 100) {
		logResponse(forwardResponse(br));
	}
}

// This is actually called when we want to simulate a ringing event, for example when a push notification is sent to a
// device.
void ForkCallContext::sendRinging() {
	int code = getLastResponseCode();
	if (code < 180 && mIncoming) {
		shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_180_RINGING));
		if (msgsip) {
			shared_ptr<ResponseSipEvent> ev(
				new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
			// add a to tag, no set by sofia here.
			if (!mCfg->mRemoveToTag) {
				const char *totag = nta_agent_newtag(msgsip->getHome(), "%s", mAgent->getSofiaAgent());
				sip_to_tag(msgsip->getHome(), msgsip->getSip()->sip_to, totag);
			}
			if (mPushTimer)
				su_timer_destroy(mPushTimer), mPushTimer = NULL;
			if (mCfg->mPushResponseTimeout > 0) {
				mPushTimer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
				su_timer_set_interval(mPushTimer, &ForkCallContext::sOnPushTimer, this,
									  (su_duration_t)mCfg->mPushResponseTimeout * 1000);
			}
			forwardResponse(ev);
		}
	}
}

void ForkCallContext::logResponse(const shared_ptr<ResponseSipEvent> &ev) {
	if (ev) {
		sip_t *sip = ev->getMsgSip()->getSip();
		mLog->setStatusCode(sip->sip_status->st_status, sip->sip_status->st_phrase);
		if (sip->sip_status->st_status >= 200)
			mLog->setCompleted();
		ev->setEventLog(mLog);
	}
}

bool ForkCallContext::onNewRegister(const url_t *url, const string &uid) {
	if (isCompleted())
		return false;
	return ForkContext::onNewRegister(url, uid);
}

bool ForkCallContext::isCompleted() const {
	if (getLastResponseCode() >= 200 || mCancelled || mIncoming == NULL)
		return true;
	return false;
}

bool ForkCallContext::isRingingSomewhere()const{
	const auto & branches = getBranches();
	for (auto it = branches.begin(); it != branches.end(); ++it){
		int status = (*it)->getStatus();
		if (status >= 180 && status < 200)
			return true;
	}
	return false;
}

void ForkCallContext::onShortTimer() {
	LOGD("ForkCallContext [%p]: time to send urgent replies", this);
	/*first stop the timer, it has to be one shot*/
	su_timer_destroy(mShortTimer);
	mShortTimer = NULL;

	if (isRingingSomewhere())
		return; /*it's ringing somewhere*/
	auto br = findBestBranch(getUrgentCodes(), mCfg->mForkLate);
	if (br) {
		logResponse(forwardResponse(br));
	}
}

void ForkCallContext::onLateTimeout() {
	auto br = findBestBranch(getUrgentCodes(), mCfg->mForkLate);
	if (!br || br->getStatus() == 0 || br->getStatus() == 503) {
		shared_ptr<MsgSip> msgsip(mIncoming->createResponse(SIP_408_REQUEST_TIMEOUT));
		if (msgsip) {
			shared_ptr<ResponseSipEvent> ev(
				new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(mAgent->shared_from_this()), msgsip));
			logResponse(forwardResponse(ev));
		}
	} else {
		logResponse(forwardResponse(br));
	}
	/*cancel all possibly pending outgoing transactions*/
	cancelOthers(shared_ptr<BranchInfo>(), NULL);
}

void ForkCallContext::sOnShortTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	ForkCallContext *zis = static_cast<ForkCallContext *>(arg);
	zis->onShortTimer();
}

void ForkCallContext::onPushTimer() {
	if (!isCompleted() && getLastResponseCode() < 180) {
		SLOGD << "ForkCallContext " << this << " push timer : no uac response";
	}
	su_timer_destroy(mPushTimer);
	mPushTimer = NULL;
}

void ForkCallContext::sOnPushTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	ForkCallContext *zis = static_cast<ForkCallContext *>(arg);
	zis->onPushTimer();
}
void ForkCallContext::onPushInitiated(const string &key) {
	++mActivePushes;
}

void ForkCallContext::onPushError(const string &key, const string &errormsg) {
	--mActivePushes;
	if (mActivePushes != 0)
		return;
	SLOGD << "Early fail due to all push requests having failed";
	onPushTimer();
}
