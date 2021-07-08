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

#include <flexisip/agent.hh>
#include <flexisip/forkcontext.hh>
#include <flexisip/registrardb.hh>
#include <sofia-sip/sip_status.h>

using namespace std;
using namespace flexisip;

const int ForkContext::sUrgentCodes[] = {401, 407, 415, 420, 484, 488, 606, 603, 0};

const int ForkContext::sAllCodesUrgent[] = {-1, 0};

ForkContext::ForkContext(Agent *agent, const shared_ptr<RequestSipEvent> &event, shared_ptr<ForkContextConfig> cfg,
						 ForkContextListener *listener, weak_ptr<StatPair> counter)
	: mListener(listener), mNextBranchesTimer(agent->getRoot()), mStatCounter(move(counter)), mCurrentPriority(-1),
	  mAgent(agent), mEvent(make_shared<RequestSipEvent>(event)), // Is this deep copy really necessary ?
	  mCfg(move(cfg)), mLateTimer(agent->getRoot()), mFinishTimer(agent->getRoot()) {
	if (auto sharedCounter = mStatCounter.lock()) {
		sharedCounter->incrStart();
	}
	init();
}

ForkContext::~ForkContext() {
	if (auto sharedCounter = mStatCounter.lock()) {
		sharedCounter->incrFinish();
	}
}

void ForkContext::processLateTimeout() {
	mLateTimer.reset();
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
	uid_finder(const string &uid) : mUid(uid) {
	}
	bool operator()(const shared_ptr<BranchInfo> &br) {
		return mUid == br->mUid;
	}
	const string mUid;
};


shared_ptr<BranchInfo> ForkContext::findBranchByUid(const string &uid) {
	auto it = find_if(mWaitingBranches.begin(), mWaitingBranches.end(), uid_finder(uid));

	if (it != mWaitingBranches.end())
		return *it;

	return shared_ptr<BranchInfo>();
}

shared_ptr<BranchInfo> ForkContext::findBranchByDest(const url_t *dest) {
	auto it = find_if(mWaitingBranches.begin(), mWaitingBranches.end(), dest_finder(dest));

	if (it != mWaitingBranches.end())
		return *it;

	return shared_ptr<BranchInfo>();
}

bool ForkContext::isUrgent(int code, const int urgentCodes[]) {
	if (urgentCodes[0] == -1)
		return true; /*everything is urgent*/

	for (int i = 0; urgentCodes[i] != 0; i++) {
		if (code == urgentCodes[i])
			return true;
	}

	return false;
}

static bool isConsidered(int code, bool ignore503And408){
	return ignore503And408 ? (!(code == 503 || code == 408)) : true;
}

shared_ptr<BranchInfo> ForkContext::_findBestBranch(const int urgentCodes[], bool ignore503And408) {
	shared_ptr<BranchInfo> best;

	for (const auto& br : mWaitingBranches) {
		int code = br->getStatus();
		if (code >= 200 && isConsidered(code, ignore503And408)) {
			if (best == NULL) {
				best = br;
			} else {
				if (br->getStatus() / 100 < best->getStatus() / 100)
					best = br;
			}
		}
	}

	if (best == NULL)
		return shared_ptr<BranchInfo>();

	if (urgentCodes) {
		for (const auto& br : mWaitingBranches) {
			int code = br->getStatus();

			if (code > 0  && isConsidered(code, ignore503And408) && isUrgent(code, urgentCodes)) {
				best = br;
				break;
			}
		}
	}

	return best;
}

shared_ptr<BranchInfo> ForkContext::findBestBranch(const int urgentCodes[], bool avoid503And408){
	shared_ptr<BranchInfo> ret;

	if (avoid503And408 == false)
		ret = _findBestBranch(urgentCodes, false);
	else {
		ret = _findBestBranch(urgentCodes, true);

		if (ret == NULL)
			ret = _findBestBranch(urgentCodes, false);
	}

	return ret;
}

bool ForkContext::allBranchesAnswered(bool ignore_errors_and_timeouts) const {
	for (const auto& br : mWaitingBranches) {
		int code = br->getStatus();

		if (code < 200)
			return false;
		if ((code == 503 || code == 408) && ignore_errors_and_timeouts)
			return false;
	}

	return true;
}

bool ForkContext::allCurrentBranchesAnswered(bool ignore_errors_and_timeouts) const {
	for (const auto& br : mCurrentBranches) {
		int code = br->getStatus();

		if (code < 200)
			return false;
		if ((code == 503 || code == 408) && ignore_errors_and_timeouts)
			return false;
	}

	return true;
}

void ForkContext::removeBranch(const shared_ptr<BranchInfo> &br) {
	SLOGD << "ForkContext [" << this << "] branch [" << br.get() << "] removed.";

	mWaitingBranches.remove(br);
	mCurrentBranches.remove(br);
	br->clear();
}

const list<shared_ptr<BranchInfo>> &ForkContext::getBranches() const {
	return mWaitingBranches;
}

// this implementation looks for already pending or failed transactions and then rejects handling of a new one that
// would already been tried.
bool ForkContext::onNewRegister(const url_t *url, const string &uid) {
	shared_ptr<BranchInfo> br, br_by_url;

	/*
	 * Check gruu. If the request was targeting a gruu address, the uid of the contact who has just registered shall match.
	 */
	string target_gr;
	if (ModuleToolbox::getUriParameter(mEvent->getSip()->sip_request->rq_url, "gr", target_gr)) {
		if (uid.find(target_gr) == string::npos){ //to compare regardless of < >
			/* This request was targetting a gruu address, but this REGISTER is not coming from our target contact.*/
			return false;
		}
	}

	br = findBranchByUid(uid);
	br_by_url = findBranchByDest(url);
	if (br) {
		int code = br->getStatus();
		if (code == 503 || code == 408){
			LOGD("ForkContext %p: onNewRegister(): instance failed to receive the request previously.", this);
			return true;
		} else if (code >= 200) {
			/*
			 * This instance has already accepted or declined the request.
			 * We should not send it the request again.
			 */
			LOGD("ForkContext %p: onNewRegister(): instance has already answered the request.", this);
			return false;
		} else {
			/*
			 * No response, or a provisional response is received. We can cannot conclude on what to do.
			 * The transaction might succeeed in near future, or it might be dead.
			 * However, if the contact's uri is new, there is a high probability that the client reconnected
			 * from a new socket, in which case the current branch will receive no response.
			 */
			if (br_by_url == nullptr){
				LOGD("ForkContext %p: onNewRegister(): instance reconnected.", this);
				return true;
			}
		}
	}
	if (br_by_url) {
		LOGD("ForkContext %p: onNewRegister(): pending transaction for this destination.", this);
		return false;
	}
	return true;
}

void ForkContext::init() {
	mIncoming = mEvent->createIncomingTransaction();

	if (mCfg->mForkLate && !mLateTimer.isRunning()) {
		/*this timer is for when outgoing transaction all die prematuraly, we still need to wait that late register
		 * arrive.*/
		mLateTimer.set([this](){processLateTimeout();}, static_cast<su_duration_t>(mCfg->mDeliveryTimeout) * 1000);
	}
}

bool compareGreaterBranch(const shared_ptr<BranchInfo> &lhs, const shared_ptr<BranchInfo> &rhs) {
	return lhs->mPriority > rhs->mPriority;
}

void ForkContext::addBranch(const shared_ptr<RequestSipEvent> &ev, const shared_ptr<ExtendedContact> &contact) {
	auto ot = ev->createOutgoingTransaction();
	auto br = createBranchInfo();

	if (mIncoming && mWaitingBranches.size() == 0) {
		/*for some reason shared_from_this() cannot be invoked within the ForkContext constructor, so we do this
		 * initialization now*/
		mIncoming->setProperty<ForkContext>("ForkContext", weak_ptr<ForkContext>{shared_from_this()});
	}

	// unlink the incoming and outgoing transactions which is done by default, since now the forkcontext is managing
	// them.
	ev->unlinkTransactions();
	br->mRequest = ev;
	br->mTransaction = ot;
	br->mUid = contact->mUniqueId;
	br->mContact = contact;
	br->mPriority = contact->mQ;

	ot->setProperty("BranchInfo", weak_ptr<BranchInfo>{br});

	// Clear answered branches with same uid.
	auto oldBr = findBranchByUid(br->mUid);
	if (oldBr && oldBr->getStatus() >= 200){
		LOGD("ForkContext [%p]: new fork branch [%p] clears out old branch [%p]", this, br.get(), oldBr.get());
		removeBranch(oldBr);
		br->mPushSent = oldBr->mPushSent; /* We need to remember if a push was sent for this branch, because in some cases (iOS) we must
				absolutely not re-send a new one.*/
	}

	onNewBranch(br);

	mWaitingBranches.push_back(br);
	mWaitingBranches.sort(compareGreaterBranch);

	if (mCurrentPriority != -1 && mCurrentPriority <= br->mPriority) {
		mCurrentBranches.push_back(br);
		mAgent->injectRequestEvent(br->mRequest);
	}

	LOGD("ForkContext [%p]: new fork branch [%p]", this, br.get());
}

shared_ptr<ForkContext> ForkContext::get(const shared_ptr<IncomingTransaction> &tr) {
	return tr->getProperty<ForkContext>("ForkContext");
}

shared_ptr<ForkContext> ForkContext::get(const shared_ptr<OutgoingTransaction> &tr) {
	shared_ptr<BranchInfo> br = getBranchInfo(tr);
	return br ? br->mForkCtx.lock() : nullptr;
}

shared_ptr<BranchInfo> ForkContext::getBranchInfo(const shared_ptr<OutgoingTransaction> &tr){
	return tr->getProperty<BranchInfo>("BranchInfo");
}

bool ForkContext::processCancel(const shared_ptr<RequestSipEvent> &ev) {
	auto transaction = dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent());

	if (transaction && ev->getMsgSip()->getSip()->sip_request->rq_method == sip_method_cancel) {
		auto ctx = ForkContext::get(transaction);

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
	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction) {
		auto binfo = getBranchInfo(transaction);
		if (binfo) {
			auto copyEv = make_shared<ResponseSipEvent>(ev); // make a copy
			copyEv->suspendProcessing();
			binfo->mLastResponse = copyEv;

			auto forkCtx = binfo->mForkCtx.lock();
			forkCtx->onResponse(binfo, copyEv);

			// the event may go through but it will not be sent*/
			ev->setIncomingAgent(nullptr);

			if (!copyEv->isSuspended()) {
				// LOGD("A response has been submitted");
				// copyEv has been resubmited, so stop original event.
				ev->terminateProcessing();
			} else {
				// LOGD("The response has been retained");
			}

			if (forkCtx->allCurrentBranchesAnswered() && forkCtx->hasNextBranches()) {
				forkCtx->start();
			}

			return true;
		} else {
			// LOGD("ForkContext: un-processed response");
		}
	}

	return false;
}

void ForkContext::onNextBranches() {
	if (hasNextBranches())
		start();
}

bool ForkContext::hasNextBranches() {
	const auto& wBrs = mWaitingBranches;
	auto findCond = [this] (const auto& br) {return br->mPriority < mCurrentPriority;};
	return !mFinished && (
		( mCurrentPriority == -1 && !mWaitingBranches.empty() ) ||
		find_if(wBrs.cbegin(), wBrs.cend(), findCond) != wBrs.cend()
	);
}

void ForkContext::nextBranches() {
	/* Clear all current branches is there is any */
	mCurrentBranches.clear();

	/* Get next priority value */
	if (mCurrentPriority == -1 && !mWaitingBranches.empty()) {
		mCurrentPriority = mWaitingBranches.front()->mPriority;
	} else {
		for(const auto& br : mWaitingBranches) {
			if (br->mPriority < mCurrentPriority) {
				mCurrentPriority = br->mPriority;
				break;
			}
		}
	}

	/* Stock all wanted branches */
	for(const auto& br : mWaitingBranches) {
		if (br->mPriority == mCurrentPriority)
			mCurrentBranches.push_back(br);
	}
}

void ForkContext::start() {
	if (mFinished) {
		LOGE("Calling start() on a completed ForkContext[%p]. Doing nothing", this);
		return;
	}

	/* Remove existing timer */
	mNextBranchesTimer.reset();

	/* Prepare branches */
	nextBranches();

	LOGD("Started forking branches with priority [%p]: %f", this, mCurrentPriority);

	/* Start the processing */
	for(const auto& br : mCurrentBranches) {
		mAgent->injectRequestEvent(br->mRequest);
	}

	if (mCfg->mCurrentBranchesTimeout > 0 && hasNextBranches()) {
		/* Start the timer for next branches */
		mNextBranchesTimer.set([this](){onNextBranches();}, static_cast<su_duration_t>(mCfg->mCurrentBranchesTimeout) * 1000);
	}
}

const shared_ptr<RequestSipEvent> &ForkContext::getEvent() {
	return mEvent;
}

void ForkContext::onFinished() {
	mFinishTimer.reset();

	// force references to be loosed immediately, to avoid circular dependencies.
	mEvent.reset();
	mIncoming.reset();

	for_each(mWaitingBranches.begin(), mWaitingBranches.end(), mem_fn(&BranchInfo::clear));
	mWaitingBranches.clear();

	for_each(mCurrentBranches.begin(), mCurrentBranches.end(), mem_fn(&BranchInfo::clear));
	mCurrentBranches.clear();

	mListener->onForkContextFinished(shared_from_this());
}

void ForkContext::setFinished() {
	if (mFinishTimer.isRunning()) {
		/*already finishing, ignore*/
		return;
	}
	mFinished = true;

	mLateTimer.reset();
	mNextBranchesTimer.reset();

	mFinishTimer.set([self = shared_from_this()](){self->onFinished();}, 0);
}

bool ForkContext::shouldFinish() {
	return true;
}

void ForkContext::onNewBranch(const shared_ptr<BranchInfo> &br) {
}

void ForkContext::onCancel(const shared_ptr<RequestSipEvent> &ev) {
}

void ForkContext::addKey(const string &key) {
     mKeys.push_back(key);
}

const list<string> &ForkContext::getKeys() const{
     return mKeys;
}

shared_ptr<BranchInfo> ForkContext::createBranchInfo() {
	return make_shared<BranchInfo>(shared_from_this());
}

// called by implementors to request the forwarding of a response from this branch, regardless of whether it was
// retained previously or not*/
shared_ptr<ResponseSipEvent> ForkContext::forwardResponse(const shared_ptr<BranchInfo> &br) {
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

	return shared_ptr<ResponseSipEvent>();
}

shared_ptr<ResponseSipEvent> ForkContext::forwardResponse(const shared_ptr<ResponseSipEvent> &ev) {
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

			if (shouldFinish())
				setFinished();
		}

		return ev;
	}

	return shared_ptr<ResponseSipEvent>();
}

int ForkContext::getLastResponseCode() const {
	if (mLastResponseSent)
		return mLastResponseSent->getMsgSip()->getSip()->sip_status->st_status;

	return 0;
}

void ForkContext::onPushSent(const std::shared_ptr<OutgoingTransaction> &tr){
	shared_ptr<BranchInfo> br = getBranchInfo(tr);
	if (!br){
		LOGE("ForkContext[%p]: no branch for transaction [%p]", this, tr.get());
		return;
	}
	br->mPushSent = true;
}

void ForkContext::onPushError(const std::shared_ptr<OutgoingTransaction> &tr, const std::string &errormsg){
}

void BranchInfo::clear() {
	mTransaction.reset();
	mRequest.reset();
	mLastResponse.reset();
	mForkCtx.reset();
}
