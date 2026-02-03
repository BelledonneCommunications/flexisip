/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "fork-context-base.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/branch-info.hh"
#include "registrar/registrar-db.hh"
#include "router/injector.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

ForkContextBase::ForkContextBase(AgentInterface* agent,
                                 const std::shared_ptr<ForkContextConfig>& cfg,
                                 const std::weak_ptr<InjectorListener>& injectorListener,
                                 const std::weak_ptr<ForkContextListener>& forkContextListener,
                                 std::unique_ptr<RequestSipEvent>&& event,
                                 const std::weak_ptr<StatPair>& counter,
                                 sofiasip::MsgSipPriority priority,
                                 bool isRestored)
    : mAgent(agent), mCfg(cfg), mLateTimer(mAgent->getRoot()), mFinishTimer(mAgent->getRoot()),
      mNextBranchesTimer(mAgent->getRoot()), mMsgPriority(priority), mInjectorListener(injectorListener),
      mForkContextListener(forkContextListener), mEvent(std::move(event)), mStatCounter(counter),
      mLogPrefix(LogManager::makeLogPrefixForInstance(this, "ForkContextBase")) {
	if (const auto statCounter = mStatCounter.lock()) {
		statCounter->incrStart();
	} else {
		LOGE << "Failed to increment counter (std::weak_ptr is empty)";
	}

	if (!isRestored) {
		mIncoming = mEvent->createIncomingTransaction();
		if (mCfg->mForkLate) {
			// this timer is for when outgoing transaction all die prematurely, we still need to wait that late register
			// arrive.
			mLateTimer.set([this]() { processLateTimeout(); },
			               static_cast<su_duration_t>(mCfg->mDeliveryTimeout) * 1000);
		}
	}
}

ForkContextBase::~ForkContextBase() {
	if (const auto statCounter = mStatCounter.lock()) {
		statCounter->incrFinish();
	} else {
		LOGE << "Failed to increment counter (std::weak_ptr is empty)";
	}
}

void ForkContextBase::processLateTimeout() {
	mLateTimer.reset();
	onLateTimeout();
	setFinished();
}

shared_ptr<BranchInfo> ForkContextBase::findBranchByUid(const string& uid) {
	auto branchIt = find_if(mWaitingBranches.begin(), mWaitingBranches.end(),
	                        [&uid](const std::shared_ptr<BranchInfo>& branch) { return uid == branch->getUid(); });

	if (branchIt != mWaitingBranches.end()) return *branchIt;
	return {};
}

shared_ptr<BranchInfo> ForkContextBase::findBranchByDest(const SipUri& dest) {
	auto branchIt =
	    find_if(mWaitingBranches.begin(), mWaitingBranches.end(), [&dest](const std::shared_ptr<BranchInfo>& branch) {
		    if (const auto branchDest = branch->getRequestUri(); branchDest != nullopt)
			    return dest.getHost() == branchDest->getHost() && dest.getPort() == branchDest->getPort();
		    return false;
	    });

	if (branchIt != mWaitingBranches.end()) return *branchIt;
	return {};
}

bool ForkContextBase::isUrgent(int code, const int urgentCodes[]) {
	if (urgentCodes[0] == -1) return true; /*everything is urgent*/

	for (int i = 0; urgentCodes[i] != 0; i++) {
		if (code == urgentCodes[i]) return true;
	}

	return false;
}

static bool isConsidered(int code, bool ignore503And408) {
	return ignore503And408 ? (!(code == 503 || code == 408)) : true;
}

bool ForkContextBase::isUseful4xx(int statusCode) {
	constexpr std::array<int, 5> useful4xxCodes = {401, 407, 415, 420, 484};
	return (std::find(useful4xxCodes.begin(), useful4xxCodes.end(), statusCode) != useful4xxCodes.end());
}

std::shared_ptr<BranchInfo> ForkContextBase::findBestBranch(bool ignore503And408) {
	shared_ptr<BranchInfo> best{nullptr};

	for (const auto& br : mWaitingBranches) {
		auto brStatus = br->getStatus();
		if (brStatus >= 200 && isConsidered(brStatus, ignore503And408)) {
			if (best == nullptr) {
				best = br;
				continue;
			}
			const auto bestStatus = best->getStatus();
			const auto bestClass = bestStatus / 100;
			const auto brClass = brStatus / 100;

			// Handle 2xx
			if (brClass == 2) {
				if (brStatus < bestStatus) best = br;
				continue;
			}
			if (bestClass == 2) continue;

			// Handle 6xx
			if (brClass == 6) {
				if (bestClass != 6 || (brStatus < bestStatus && bestClass == 6)) best = br;
				continue;
			}
			if (bestClass == 6) continue;

			// Handle 4xx and the rest
			if (brClass == 4 && bestClass == 4) {
				if (!isUseful4xx(bestStatus) && isUseful4xx(brStatus)) {
					best = br;
				}
			} else if (brClass < bestClass) {
				best = br;
			}
		}
	}

	return best;
}

bool ForkContextBase::allBranchesAnswered(FinalStatusMode finalStatusMode) const {
	for (const auto& br : mWaitingBranches) {
		if (br->needsDelivery(finalStatusMode)) {
			return false;
		}
	}

	return true;
}

bool ForkContextBase::allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const {
	for (const auto& br : mCurrentBranches) {
		if (br->needsDelivery(finalStatusMode)) {
			return false;
		}
	}

	return true;
}

void ForkContextBase::removeBranch(const shared_ptr<BranchInfo>& br) {
	LOGD << "Removed branch: " << br;

	mWaitingBranches.remove(br);
	mCurrentBranches.remove(br);
}

const list<shared_ptr<BranchInfo>>& ForkContextBase::getBranches() const {
	return mWaitingBranches;
}

ForkContextBase::ShouldDispatchType ForkContextBase::shouldDispatch(const SipUri& dest, const std::string& uid) {
	shared_ptr<BranchInfo> br, br_by_url;

	/*
	 * Check gruu. If the request was targeting a gruu address, the uid of the contact who has just registered shall
	 * match.
	 */
	sofiasip::Url url{mEvent->getSip()->sip_request->rq_url};
	const auto targetGr = url.getParam("gr");
	if (!targetGr.empty()) {
		if (uid.find(targetGr) == string::npos) { // to compare regardless of < >
			/* This request was targetting a gruu address, but this REGISTER is not coming from our target contact.*/
			return {.status = DispatchStatus::DispatchNotNeeded, .branch = nullptr};
		}
	}

	br = findBranchByUid(uid);
	br_by_url = findBranchByDest(dest);
	if (br) {
		int code = br->getStatus();
		if (code == 503 || code == 408) {
			LOGD << "Instance failed to receive the request previously";
			return {.status = DispatchStatus::DispatchNeeded, .branch = br};
		} else if (code >= 200) {
			/*
			 * This instance has already accepted or declined the request.
			 * We should not send it the request again.
			 */
			LOGD << "Instance has already answered the request";
			return {.status = DispatchStatus::DispatchNotNeeded, .branch = nullptr};
		} else {
			/*
			 * No response, or a provisional response is received. We can cannot conclude on what to do.
			 * The transaction might succeeed in near future, or it might be dead.
			 * However, if the contact's uri is new, there is a high probability that the client reconnected
			 * from a new socket, in which case the current branch will receive no response.
			 */
			if (br_by_url == nullptr) {
				LOGD << "Instance reconnected";
				return {.status = DispatchStatus::DispatchNeeded, .branch = br};
			}
		}
	}
	if (br_by_url) {
		LOGD << "Pending transaction for this destination";
		return {.status = DispatchStatus::PendingTransaction, .branch = nullptr};
	}

	return {.status = DispatchStatus::DispatchNeeded, .branch = nullptr};
}

// This is actually called when we want to simulate a ringing event by sending a 180, or for example to signal the
// caller that we've sent a push notification.
void ForkContextBase::sendResponse(int code, char const* phrase, bool addToTag) {
	if (!mCfg->mPermitSelfGeneratedProvisionalResponse) {
		LOGD << "Self-generated provisional response are disabled by configuration";
		return;
	}

	auto previousCode = getLastResponseCode();
	if (previousCode > code || !mIncoming) {
		// Don't send a response with status code lesser than the last transmitted response.
		return;
	}

	auto msgsip = mIncoming->createResponse(code, phrase);
	if (!msgsip) return;

	auto ev = make_unique<ResponseSipEvent>(mAgent->getOutgoingAgent(), msgsip);

	// Add a 'To' tag, no set by sofia here.
	if (addToTag) {
		auto totag = nta_agent_newtag(msgsip->getHome(), "%s", mAgent->getSofiaAgent());
		sip_to_tag(msgsip->getHome(), msgsip->getSip()->sip_to, totag);
	}

	onForwardResponse(std::move(ev));
}

shared_ptr<BranchInfo> ForkContextBase::addBranch(std::unique_ptr<RequestSipEvent>&& ev,
                                                  const std::shared_ptr<ExtendedContact>& contact) {
	if (mIncoming && mWaitingBranches.empty()) setFork(mIncoming, shared_from_this());

	int clearedCount{0};
	std::weak_ptr<BranchInfoListener> listener{};
	std::weak_ptr<PushNotificationContext> pushContext{};

	const auto oldBranch = findBranchByUid(contact->mKey);
	if (oldBranch) {
		// We need to remember how many times branches for a given uid have been cleared. Because in some cases (iOS) we
		// must absolutely not re-send a push notification, and we send one only if br->mClearedCount == 0 (See
		// PushNotification::makePushNotification).
		clearedCount = oldBranch->getClearedCount() + 1;
		// The listener of the old branch must be moved in the new one to be notified of the last events about the
		// actual UID.
		listener = oldBranch->getListener();
		pushContext = oldBranch->getPushNotificationContext();
	}

	const auto branch =
	    BranchInfo::make(std::move(ev), shared_from_this(), contact, listener, pushContext, clearedCount);

	// Clear answered branch with the same uid.
	if (oldBranch && oldBranch->getStatus() >= 200) {
		LOGD << "New " << branch.get() << " clears out old " << oldBranch.get() << " (UID = " << contact->mKey.str()
		     << ")";
		removeBranch(oldBranch);
	}

	onNewBranch(branch);

	mWaitingBranches.push_back(branch);
	mWaitingBranches.sort([](const std::shared_ptr<BranchInfo>& lhs, const std::shared_ptr<BranchInfo>& rhs) {
		return lhs->getPriority() > rhs->getPriority();
	});

	// If mCurrentPriority != -1 it means that this fork is already started.
	if (mCurrentPriority != -1 && mCurrentPriority <= branch->getPriority()) {
		mCurrentBranches.push_back(branch);
		if (const auto injectorListener = mInjectorListener.lock()) {
			injectorListener->inject(branch->extractRequest(), shared_from_this(), contact->contactId());
		} else {
			mAgent->injectRequestEvent(branch->extractRequest());
		}
	}

	return branch;
}

void ForkContextBase::onNextBranches() {
	if (hasNextBranches()) start();
}

bool ForkContextBase::hasNextBranches() const {
	const auto& wBrs = mWaitingBranches;
	auto findCond = [this](const auto& br) { return br->getPriority() < mCurrentPriority; };
	return !mFinished && ((mCurrentPriority == -1 && !mWaitingBranches.empty()) ||
	                      find_if(wBrs.cbegin(), wBrs.cend(), findCond) != wBrs.cend());
}

void ForkContextBase::nextBranches() {
	/* Clear all current branches is there is any */
	mCurrentBranches.clear();

	/* Get next priority value */
	if (mCurrentPriority == -1 && !mWaitingBranches.empty()) {
		mCurrentPriority = mWaitingBranches.front()->getPriority();
	} else {
		for (const auto& br : mWaitingBranches) {
			if (br->getPriority() < mCurrentPriority) {
				mCurrentPriority = br->getPriority();
				break;
			}
		}
	}

	/* Stock all wanted branches */
	for (const auto& br : mWaitingBranches) {
		if (br->getPriority() == mCurrentPriority) mCurrentBranches.push_back(br);
	}
}

void ForkContextBase::start() {
	if (mFinished) {
		LOGE << "Calling start() on a completed: do nothing";
		return;
	}

	/* Remove existing timer */
	mNextBranchesTimer.reset();

	/* Prepare branches */
	nextBranches();

	LOGD << "Started forking branches with priority: " << mCurrentPriority;

	/* Start the processing */
	for (const auto& br : mCurrentBranches) {
		if (const auto injectorListener = mInjectorListener.lock()) {
			injectorListener->inject(br->extractRequest(), shared_from_this(), br->getContact()->contactId());
		} else {
			mAgent->injectRequestEvent(br->extractRequest());
		}

		// Can only occur if an internal error append
		if (mCurrentBranches.empty()) break;
	}

	// Start the timer for the next branches.
	if (mCfg->mCurrentBranchesTimeout > 0 && hasNextBranches())
		mNextBranchesTimer.set(
		    [this] {
			    LOGD << "Timer 'call-fork-current-branches-timeout' triggered";
			    onNextBranches();
		    },
		    static_cast<su_duration_t>(mCfg->mCurrentBranchesTimeout) * 1000);
}

RequestSipEvent& ForkContextBase::getEvent() {
	return *mEvent;
}

sofiasip::MsgSipPriority ForkContextBase::getMsgPriority() const {
	return mMsgPriority;
}

const std::shared_ptr<ForkContextConfig>& ForkContextBase::getConfig() const {
	return mCfg;
}

void ForkContextBase::onFinished() {
	if (const auto forkContextListener = mForkContextListener.lock()) {
		forkContextListener->onForkContextFinished(shared_from_this());
	} else {
		LOGE << "Failed to notify ForkContextListener that fork is finished (std::weak_ptr of listener is empty)";
	}
}

void ForkContextBase::setFinished() {
	if (mFinishTimer.isRunning()) {
		/*already finishing, ignore*/
		return;
	}
	mFinished = true;

	mLateTimer.reset();
	mNextBranchesTimer.reset();

	mFinishTimer.set(
	    [weak = weak_ptr<ForkContextBase>{shared_from_this()}]() {
		    if (auto shared = weak.lock()) {
			    shared->onFinished();
		    }
	    },
	    0ms);
}

bool ForkContextBase::shouldFinish() {
	return true;
}

std::unique_ptr<ResponseSipEvent> ForkContextBase::onForwardResponse(std::unique_ptr<ResponseSipEvent>&& event) {
	if (mIncoming == nullptr) return {};

	const int code = event->getMsgSip()->getSip()->sip_status->st_status;
	event->setIncomingAgent(mIncoming);
	mLastResponseSent = event->getMsgSip();

	if (event->isSuspended()) {
		event = mAgent->injectResponseEvent(std::move(event));
	} else {
		event = mAgent->sendResponseEvent(std::move(event));
	}

	if (code >= 200) {
		mIncoming.reset();
		if (shouldFinish()) setFinished();
	}

	return std::move(event);
}

void ForkContextBase::onCancel(const MsgSip&) {
	if (shouldFinish()) {
		setFinished();
	}
}

void ForkContextBase::onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent&) {
	if (br->getStatus() >= 200) br->notifyBranchCompleted();
}

bool ForkContextBase::isFinished() const {
	return mFinished;
}

void ForkContextBase::onPushSent(PushNotificationContext& aPNCtx, bool) noexcept {
	if (!m110Sent) {
		sendResponse(110, "Push sent", aPNCtx.toTagEnabled());
		m110Sent = true;
	}
}

void ForkContextBase::addKey(const string& key) {
	mKeys.push_back(key);
}

const vector<string>& ForkContextBase::getKeys() const {
	return mKeys;
}

int ForkContextBase::getLastResponseCode() const {
	if (mLastResponseSent) return mLastResponseSent->getSip()->sip_status->st_status;

	return 0;
}

unique_ptr<ResponseSipEvent> ForkContextBase::forwardCustomResponse(int status, const char* phrase) {
	if (mIncoming == nullptr) {
		LOGD << "Cannot forward SIP response [" << status << " " << phrase << "]: no incoming transaction";
		return {};
	}
	auto msgsip = mIncoming->createResponse(status, phrase);
	if (msgsip) {
		auto ev = make_unique<ResponseSipEvent>(mAgent->getOutgoingAgent(), msgsip);
		return onForwardResponse(std::move(ev));
	} else { // Should never happen
		LOGE << "Fork error: MsgSip cannot be created, fork is completed without forwarding any response";
		setFinished();
	}
	return {};
}

void ForkContextBase::processInternalError(int status, const char* phrase) {
	forwardCustomResponse(status, phrase);
}

std::shared_ptr<BranchInfo> ForkContextBase::checkFinished() {
	if (mIncoming == nullptr && !mCfg->mForkLate) {
		setFinished();
		return nullptr;
	}

	if (allBranchesAnswered(FinalStatusMode::RFC)) {
		const auto& br = findBestBranch(mCfg->mForkLate);

		if (mCfg->mForkLate && allBranchesAnswered(FinalStatusMode::ForkLate)) {
			setFinished();
		} else if (!mCfg->mForkLate) {
			setFinished();
		}

		if (br && br->forwardResponse(mIncoming != nullptr)) return br;
	}

	return nullptr;
}

const ForkContext* ForkContextBase::getPtrForEquality() const {
	return this;
}