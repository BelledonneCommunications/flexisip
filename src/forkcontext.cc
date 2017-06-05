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

#include "forkcontext.hh"
#include "registrardb.hh"
#include <sofia-sip/sip_status.h>
using namespace std;

const int ForkContext::sUrgentCodes[] = {401, 407, 415, 420, 484, 488, 606, 603, 0};

const int ForkContext::sAllCodesUrgent[] = {-1, 0};

ForkContextConfig::ForkContextConfig()
	: mDeliveryTimeout(0), mUrgentTimeout(5), mForkLate(false), mTreatAllErrorsAsUrgent(false),
	  mForkNoGlobalDecline(false), mTreatDeclineAsUrgent(false), mRemoveToTag(false) {
}

ForkContextListener::~ForkContextListener() {
}

void ForkContext::__timer_callback(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	(static_cast<ForkContext *>(arg))->processLateTimeout();
}

void ForkContext::sOnFinished(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg) {
	(static_cast<ForkContext *>(arg))->onFinished();
}

ForkContext::ForkContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg,
						 ForkContextListener *listener)
	: mListener(listener), mAgent(agent),
	  mEvent(make_shared<RequestSipEvent>(event)), // Is this deep copy really necessary ?
	  mCfg(cfg), mLateTimer(NULL), mFinishTimer(NULL) {
	init();
}

void ForkContext::onLateTimeout() {
}

void ForkContext::processLateTimeout() {
	su_timer_destroy(mLateTimer);
	mLateTimer = NULL;
	onLateTimeout();
	setFinished();
}

struct dest_finder {
	dest_finder(const url_t *ctt) {
		cttport = url_port(ctt);
		ctthost = ctt->url_host;
		// don't care about transport
	}
	bool operator()(const shared_ptr<BranchInfo> &br) {
		const url_t *dest = br->mRequest->getMsgSip()->getSip()->sip_request->rq_url;
		return 0 == strcmp(url_port(dest), cttport) && 0 == strcmp(dest->url_host, ctthost);
	}
	const char *ctthost;
	const char *cttport;
};

struct uid_finder {
	uid_finder(const std::string &uid) : mUid(uid) {
	}
	bool operator()(const shared_ptr<BranchInfo> &br) {
		return mUid == br->mUid;
	}
	const string mUid;
};

std::shared_ptr<BranchInfo> ForkContext::findBranchByUid(const std::string &uid) {
	auto it = find_if(mBranches.begin(), mBranches.end(), uid_finder(uid));
	if (it != mBranches.end())
		return *it;
	return shared_ptr<BranchInfo>();
}

std::shared_ptr<BranchInfo> ForkContext::findBranchByDest(const url_t *dest) {
	auto it = find_if(mBranches.begin(), mBranches.end(), dest_finder(dest));
	if (it != mBranches.end())
		return *it;
	return shared_ptr<BranchInfo>();
}

bool ForkContext::isUrgent(int code, const int urgentCodes[]) {
	int i;
	if (urgentCodes[0] == -1)
		return true; /*everything is urgent*/
	for (i = 0; urgentCodes[i] != 0; i++) {
		if (code == urgentCodes[i])
			return true;
	}
	return false;
}

static bool isConsidered(int code, bool ignore503And408){
	return ignore503And408 ? (!(code == 503 || code == 408)) : true;
}

std::shared_ptr<BranchInfo> ForkContext::_findBestBranch(const int urgentCodes[], bool ignore503And408) {
	shared_ptr<BranchInfo> best;
	
	for (auto it = mBranches.begin(); it != mBranches.end(); ++it) {
		int code = (*it)->getStatus();
		if (code >= 200 && isConsidered(code, ignore503And408)) {
			if (best == NULL) {
				best = (*it);
			} else {
				if ((*it)->getStatus() / 100 < best->getStatus() / 100)
					best = (*it);
			}
		}
	}
	if (best == NULL)
		return shared_ptr<BranchInfo>();
	if (urgentCodes) {
		for (auto it = mBranches.begin(); it != mBranches.end(); ++it) {
			int code = (*it)->getStatus();
			if (code > 0  && isConsidered(code, ignore503And408) && isUrgent(code, urgentCodes)) {
				best = (*it);
				break;
			}
		}
	}
	return best;
}

std::shared_ptr<BranchInfo> ForkContext::findBestBranch(const int urgentCodes[], bool avoid503And408){
	std::shared_ptr<BranchInfo> ret;
	if (avoid503And408 == false){
		ret = _findBestBranch(urgentCodes, false);
	}else{
		ret = _findBestBranch(urgentCodes, true);
		if (ret == NULL) ret = _findBestBranch(urgentCodes, false);
	}
	return ret;
}

bool ForkContext::allBranchesAnswered(bool ignore_errors_and_timeouts) const {
	for (auto it = mBranches.begin(); it != mBranches.end(); ++it) {
		int code = (*it)->getStatus();
		if (code < 200)
			return false;
		if ((code == 503 || code == 408) && ignore_errors_and_timeouts)
			return false;
	}
	return true;
}

void ForkContext::removeBranch(const shared_ptr<BranchInfo> &br) {
	LOGD("ForkContext [%p] branch [%p] removed.", this, br.get());
	mBranches.remove(br);
	br->clear();
}

const std::list<std::shared_ptr<BranchInfo>> &ForkContext::getBranches() const{
	return mBranches;
}

// this implementation looks for already pending or failed transactions and then rejects handling of a new one that
// would already been tried.
bool ForkContext::onNewRegister(const url_t *url, const string &uid) {
	shared_ptr<BranchInfo> br = findBranchByDest(url);
	if (br) {
		LOGD("ForkContext %p: onNewRegister(): destination already handled.", this);
		return false;
	}
	br = findBranchByUid(uid);
	if (br){
		int code = br->getStatus();
		if (code >= 300 && code != 503 && code != 408){
			/* This instance has already declined the call, but has reconnected using another transport address.
			 * We should not send it the message again.
			 */
			LOGD("ForkContext %p: onNewRegister(): instance has already declined the request.", this);
			return false;
		}
	}
	return true;
}

void ForkContext::init() {
	mIncoming = mEvent->createIncomingTransaction();
	if (mCfg->mForkLate && mLateTimer == NULL) {
		/*this timer is for when outgoing transaction all die prematuraly, we still need to wait that late register
		 * arrive.*/
		mLateTimer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
		su_timer_set_interval(mLateTimer, &ForkContext::__timer_callback, this,
							  (su_duration_t)mCfg->mDeliveryTimeout * (su_duration_t)1000);
	}
}

void ForkContext::addBranch(const shared_ptr<RequestSipEvent> &ev, const shared_ptr<ExtendedContact> &contact) {
	shared_ptr<OutgoingTransaction> ot = ev->createOutgoingTransaction();
	shared_ptr<BranchInfo> br = createBranchInfo();

	if (mIncoming && mBranches.size() == 0) {
		/*for some reason shared_from_this() cannot be invoked within the ForkContext constructor, so we do this
		 * initialization now*/
		mIncoming->setProperty<ForkContext>("ForkContext", shared_from_this());
	}
	// unlink the incoming and outgoing transactions which is done by default, since now the forkcontext is managing
	// them.
	ev->unlinkTransactions();
	br->mRequest = ev;
	br->mTransaction = ot;
	br->mUid = contact->mUniqueId;
	br->mContact = contact;
	ot->setProperty("BranchInfo", br);
	onNewBranch(br);
	mBranches.push_back(br);
	LOGD("ForkContext [%p] new fork branch [%p]", this, br.get());
}

std::shared_ptr<ForkContext> ForkContext::get(const std::shared_ptr<IncomingTransaction> &tr) {
	return tr->getProperty<ForkContext>("ForkContext");
}

std::shared_ptr<ForkContext> ForkContext::get(const std::shared_ptr<OutgoingTransaction> &tr) {
	shared_ptr<BranchInfo> br = tr->getProperty<BranchInfo>("BranchInfo");
	return br ? br->mForkCtx : shared_ptr<ForkContext>();
}

bool ForkContext::processCancel(const std::shared_ptr<RequestSipEvent> &ev) {
	shared_ptr<IncomingTransaction> transaction = dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());
	if (transaction && ev->getMsgSip()->getSip()->sip_request->rq_method == sip_method_cancel) {
		shared_ptr<ForkContext> ctx = ForkContext::get(transaction);
		if (ctx) {
			ctx->onCancel(ev);
			if (ctx->shouldFinish())
				ctx->setFinished();
			// let ev go through all the chain, however it will not be forwarded.
			return true;
		}
	}
	return false;
}

bool ForkContext::processResponse(const shared_ptr<ResponseSipEvent> &ev) {
	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction != NULL) {
		shared_ptr<BranchInfo> binfo = transaction->getProperty<BranchInfo>("BranchInfo");
		if (binfo) {
			auto copyEv = make_shared<ResponseSipEvent>(ev); // make a copy
			copyEv->suspendProcessing();
			binfo->mLastResponse = copyEv;
			binfo->mForkCtx->onResponse(binfo, copyEv);
			// the event may go through but it will not be sent*/
			ev->setIncomingAgent(shared_ptr<IncomingAgent>());
			if (!copyEv->isSuspended()) {
				// LOGD("A response has been submitted");
				// copyEv has been resubmited, so stop original event.
				ev->terminateProcessing();
			} else {
				// LOGD("The response has been retained");
			}
			return true;
		} else {
			// LOGD("ForkContext: un-processed response");
		}
	}
	return false;
}

const shared_ptr<RequestSipEvent> &ForkContext::getEvent() {
	return mEvent;
}

ForkContext::~ForkContext() {
	if (mLateTimer)
		su_timer_destroy(mLateTimer);
}

void ForkContext::onFinished() {
	su_timer_destroy(mFinishTimer);
	mFinishTimer = NULL;
	// force references to be loosed immediately, to avoid circular dependencies.
	mEvent.reset();
	mIncoming.reset();
	for_each(mBranches.begin(), mBranches.end(), mem_fn(&BranchInfo::clear));
	mBranches.clear();
	mListener->onForkContextFinished(shared_from_this());
	mSelf.reset(); // this must be the last thing to do
}

void ForkContext::setFinished() {
	if (mFinishTimer) {
		/*already finishing, ignore*/
		return;
	}
	if (mLateTimer) {
		su_timer_destroy(mLateTimer);
		mLateTimer = NULL;
	}
	mSelf = shared_from_this(); // to prevent destruction until finishTimer arrives
	mFinishTimer = su_timer_create(su_root_task(mAgent->getRoot()), 0);
	su_timer_set_interval(mFinishTimer, &ForkContext::sOnFinished, this, (su_duration_t)0);
}

bool ForkContext::shouldFinish() {
	return true;
}

void ForkContext::onNewBranch(const std::shared_ptr<BranchInfo> &br) {
}

void ForkContext::onCancel(const std::shared_ptr<RequestSipEvent> &ev) {
}

void ForkContext::setKey(std::string key) {
     mKey = key;
}

std::string ForkContext::getKey() {
     return mKey;
}

std::shared_ptr<BranchInfo> ForkContext::createBranchInfo() {
	return make_shared<BranchInfo>(shared_from_this());
}

// called by implementors to request the forwarding of a response from this branch, regardless of whether it was
// retained previously or not*/
std::shared_ptr<ResponseSipEvent> ForkContext::forwardResponse(const std::shared_ptr<BranchInfo> &br) {
	if (br->mLastResponse) {
		if (mIncoming) {
			int code = br->mLastResponse->getMsgSip()->getSip()->sip_status->st_status;
			forwardResponse(br->mLastResponse);
			if (code >= 200) {
				br->mTransaction.reset();
			}
			return br->mLastResponse;
		} else
			br->mLastResponse->setIncomingAgent(shared_ptr<IncomingAgent>());
	} else {
		LOGE("ForkContext::forwardResponse(): no response received on this branch");
	}
	return std::shared_ptr<ResponseSipEvent>();
}

std::shared_ptr<ResponseSipEvent> ForkContext::forwardResponse(const std::shared_ptr<ResponseSipEvent> &ev) {
	if (mIncoming) {
		int code = ev->getMsgSip()->getSip()->sip_status->st_status;
		ev->setIncomingAgent(mIncoming);
		mLastResponseSent = ev;
		if (ev->isSuspended()) {
			mAgent->injectResponseEvent(ev);
		} else {
			mAgent->sendResponseEvent(ev);
		}
		if (code >= 200) {
			mIncoming.reset();
			if (shouldFinish()) {
				setFinished();
			}
		}
		return ev;
	}
	return std::shared_ptr<ResponseSipEvent>();
}

int ForkContext::getLastResponseCode() const {
	if (mLastResponseSent)
		return mLastResponseSent->getMsgSip()->getSip()->sip_status->st_status;
	return 0;
}

void BranchInfo::clear() {
	if (mTransaction) {
		mTransaction->removeProperty("BranchInfo");
		mTransaction.reset();
	}
	mRequest.reset();
	mLastResponse.reset();
	mForkCtx.reset();
}

BranchInfo::~BranchInfo() {
	clear();
}
