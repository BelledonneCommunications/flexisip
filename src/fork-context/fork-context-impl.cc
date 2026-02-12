/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "fork-context-impl.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "fork-context/branch-info.hh"
#include "modules/module-pushnotification.hh"
#include "registrar/registrar-db.hh"
#include "router/injector.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;

namespace {
string onResponseActionToString(const OnResponseAction& action) {
	switch (action) {
		case OnResponseAction::Send:
			return "send";
		case OnResponseAction::SendAndUpdate:
			return "send and update branches";
		case OnResponseAction::Wait:
			return "wait";
		case OnResponseAction::WaitAndUpdate:
			return "wait and update branches";
		default:
			return "unkown decision, nothing to do";
	}
}

string responseStrategyToString(const ResponseStrategy& strategy) {
	switch (strategy) {
		case ResponseStrategy::Best:
			return "best";
		case ResponseStrategy::BestElseDefault:
			return "best else default";
		case ResponseStrategy::Default:
			return "default";
		case ResponseStrategy::Wait:
			return "wait";
		default:
			return "unkown strategy, nothing to do";
	}
}
} // namespace

ForkContextImpl::ForkContextImpl(AgentInterface* agent,
                                 const std::shared_ptr<ForkContextConfig>& cfg,
                                 const std::weak_ptr<InjectorListener>& injectorListener,
                                 const std::weak_ptr<ForkContextListener>& forkContextListener,
                                 std::unique_ptr<RequestSipEvent>&& event,
                                 sofiasip::MsgSipPriority priority,
                                 const std::weak_ptr<StatPair>& counter,
                                 std::unique_ptr<IForkStrategy>&& forkStrategy,
                                 bool isRestored)
    : mAgent(agent), mLateTimer(mAgent->getRoot(), cfg->mDeliveryTimeout), mMsgPriority(priority),
      mForkContextListener(forkContextListener), mCfg(cfg), mDecisionTimer(mAgent->getRoot()),
      mFinishTimer(mAgent->getRoot()), mNextBranchesTimer(mAgent->getRoot()), mInjectorListener(injectorListener),
      mEvent(std::move(event)), mStatCounter(counter),
      mLogPrefix(LogManager::makeLogPrefixForInstance(
          this, string("ForkContextImpl") + "(" + forkStrategy->getStrategyName().data() + ")")),
      mStrategy(std::move(forkStrategy)) {
	mDecisionTimer.set(
	    [this] {
		    if (isRingingSomewhere()) return;
		    const auto strategy = mStrategy->chooseStrategyOnDecisionTimer();
		    LOGD << "Decision timer triggered with strategy " << responseStrategyToString(strategy);
		    applyResponseStrategy(strategy);
	    },
	    mCfg->mUrgentTimeout);
	if (const auto statCounter = mStatCounter.lock()) statCounter->incrStart();
	else LOGE << "Failed to increment counter (std::weak_ptr is empty)";

	if (!isRestored) {
		mIncoming = mEvent->createIncomingTransaction();
		// This timer is for when outgoing transaction all die prematurely, we still need to wait that late register
		// arrive.
		if (mCfg->mForkLate) mLateTimer.setForEver([this] { executeOnLateTimeout(); });
	}
}

ForkContextImpl::~ForkContextImpl() {
	LOGD << "Destroy instance";

	if (mIncoming && mIncoming->getStatus() < 200) {
		LOGE << "Fork failed to provide an answer, reply 503.";
		getEvent().reply(SIP_503_SERVICE_UNAVAILABLE, TAG_END());
	}

	if (const auto statCounter = mStatCounter.lock()) statCounter->incrFinish();
	else LOGE << "Failed to increment counter (std::weak_ptr is empty)";
}

void ForkContextImpl::executeOnLateTimeout() {
	LOGD << "Late timeout timer triggered";
	// Evaluate first as the value may change after the onLateTimeout call.
	const auto stop = shouldFinish(true);

	if (mIncoming) {
		applyResponseStrategy(mStrategy->chooseStrategyOnLateTimeout());
		for (const auto& br : mWaitingBranches) {
			mStrategy->updateBranch(br, getEvent());
		}
	}
	if (stop) setFinished();
}

shared_ptr<BranchInfo> ForkContextImpl::findBranchByUid(const string& uid) {
	auto branchIt = find_if(mWaitingBranches.begin(), mWaitingBranches.end(),
	                        [&uid](const std::shared_ptr<BranchInfo>& branch) { return uid == branch->getUid(); });

	if (branchIt != mWaitingBranches.end()) return *branchIt;
	return {};
}

shared_ptr<BranchInfo> ForkContextImpl::findBranchByDest(const SipUri& dest) {
	auto branchIt =
	    find_if(mWaitingBranches.begin(), mWaitingBranches.end(), [&dest](const std::shared_ptr<BranchInfo>& branch) {
		    if (const auto branchDest = branch->getRequestUri(); branchDest != nullopt)
			    return dest.getHost() == branchDest->getHost() && dest.getPort() == branchDest->getPort();
		    return false;
	    });

	if (branchIt != mWaitingBranches.end()) return *branchIt;
	return {};
}

static bool isConsidered(int code, bool ignore503And408) {
	return ignore503And408 ? !(code == 503 || code == 408) : true;
}

bool ForkContextImpl::isUseful4xx(int statusCode) {
	constexpr std::array<int, 5> useful4xxCodes{401, 407, 415, 420, 484};
	return find(useful4xxCodes.begin(), useful4xxCodes.end(), statusCode) != useful4xxCodes.end();
}

std::shared_ptr<BranchInfo> ForkContextImpl::findBestBranch(bool ignore503And408) const {
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

bool ForkContextImpl::allBranchesAnswered(FinalStatusMode finalStatusMode) const {
	return all_of(mWaitingBranches.cbegin(), mWaitingBranches.cend(),
	              [&](const auto& branch) { return !branch->needsDelivery(finalStatusMode); });
}

bool ForkContextImpl::allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const {
	return all_of(mCurrentBranches.cbegin(), mCurrentBranches.cend(),
	              [&](const auto& branch) { return !branch->needsDelivery(finalStatusMode); });
}

void ForkContextImpl::removeBranch(const shared_ptr<BranchInfo>& br) {
	mWaitingBranches.remove(br);
	mCurrentBranches.remove(br);
	LOGD << "Removed branch: " << br;
}

ForkContextImpl::ShouldDispatchType ForkContextImpl::shouldDispatch(const SipUri& dest, const std::string& uid) {
	/*
	 * Check gruu. If the request was targeting a gruu address, the uid of the contact who has just registered shall
	 * match.
	 */
	sofiasip::Url url{mEvent->getSip()->sip_request->rq_url};
	const auto targetGr = url.getParam("gr");
	if (!targetGr.empty()) {
		if (uid.find(targetGr) == string::npos) { // to compare regardless of < >
			// This request was targeting a GRUU address, but this REGISTER is not coming from our target contact.
			return {.status = DispatchStatus::DispatchNotNeeded, .branch = nullptr};
		}
	}

	const auto br = findBranchByUid(uid);
	const auto brByUrl = findBranchByDest(dest);
	if (br) {
		const auto code = br->getStatus();
		if (code == 503 || code == 408) {
			LOGD << "Instance failed to receive the request previously";
			return {.status = DispatchStatus::DispatchNeeded, .branch = br};
		}
		if (code >= 200) {
			/*
			 * This instance has already accepted or declined the request.
			 * We should not send it the request again.
			 */
			LOGD << "Instance has already answered the request";
			return {.status = DispatchStatus::DispatchNotNeeded, .branch = nullptr};
		}
		/*
		 * No response, or a provisional response is received. We cannot conclude on what to do.
		 * The transaction might succeed soon, or it might be dead.
		 * However, if the contact's uri is new, there is a high probability that the client reconnected
		 * from a new socket, in which case the current branch will receive no response.
		 */
		if (brByUrl == nullptr) {
			LOGD << "Instance reconnected";
			return {.status = DispatchStatus::DispatchNeeded, .branch = br};
		}
	}
	if (brByUrl) {
		LOGD << "Pending transaction for this destination";
		return {.status = DispatchStatus::PendingTransaction, .branch = nullptr};
	}

	return {.status = DispatchStatus::DispatchNeeded, .branch = nullptr};
}

// This is actually called when we want to simulate a ringing event by sending a 180, or, for example, to signal the
// caller that we've sent a push notification.
void ForkContextImpl::sendResponse(int code, char const* phrase, bool addToTag) {
	if (!mCfg->mPermitSelfGeneratedProvisionalResponse) {
		LOGD << "Self-generated provisional response are disabled by configuration";
		return;
	}

	// Don't send a response with status code lesser than the last transmitted response.
	if (const auto previousCode = getLastResponseCode(); previousCode > code || !mIncoming) return;

	auto msgsip = mIncoming->createResponse(code, phrase);
	if (!msgsip) return;

	auto ev = make_unique<ResponseSipEvent>(mAgent->getOutgoingAgent(), msgsip);

	// Add a 'To' tag, no set by sofia here.
	if (addToTag) {
		auto totag = nta_agent_newtag(msgsip->getHome(), "%s", mAgent->getSofiaAgent());
		sip_to_tag(msgsip->getHome(), msgsip->getSip()->sip_to, totag);
	}

	onSendResponse(std::move(ev));
}

shared_ptr<BranchInfo> ForkContextImpl::addBranch(std::unique_ptr<RequestSipEvent>&& ev,
                                                  const std::shared_ptr<ExtendedContact>& contact) {
	if (mIncoming && mWaitingBranches.empty()) setFork(mIncoming, shared_from_this());

	int clearedCount{0};
	std::weak_ptr<BranchInfoListener> listener{};
	std::weak_ptr<PushNotificationContext> pushContext{};

	const auto oldBranch = findBranchByUid(contact->mKey);
	if (oldBranch) {
		// We need to remember how many times branches for a given uid have been cleared. Because in some cases
		// (iOS) we must absolutely not re-send a push notification, and we send one only if br->mClearedCount == 0
		// (See PushNotification::makePushNotification).
		clearedCount = oldBranch->getClearedCount() + 1;
		// The listener of the old branch must be moved in the new one to be notified of the last events about the
		// actual UID.
		listener = oldBranch->getListener();
		pushContext = oldBranch->getPushNotificationContext();
	}

	auto branch = BranchInfo::make(std::move(ev), shared_from_this(), contact, listener, pushContext, clearedCount);

	// Clear answered branch with the same uid.
	if (oldBranch) {
		auto status = oldBranch->getStatus();
		if (status != 0 && status == 408 && status == 503) {
			LOGW << "Trying to replace an already answered branch " << oldBranch.get()
			     << " (UID = " << contact->mKey.str() << " aborting";
			return nullptr;
		}

		LOGD << "New " << branch.get() << " clears out old " << oldBranch.get() << " (UID = " << contact->mKey.str()
		     << ")";
		removeBranch(oldBranch);
	}

	mStrategy->onNewBranch(branch);

	mWaitingBranches.push_back(branch);
	mWaitingBranches.sort([](const std::shared_ptr<BranchInfo>& lhs, const std::shared_ptr<BranchInfo>& rhs) {
		return lhs->getPriority() > rhs->getPriority();
	});

	// If mCurrentPriority != -1, it means that this fork is already started.
	if (mCurrentPriority != -1.f && mCurrentPriority <= branch->getPriority()) {
		mCurrentBranches.push_back(branch);
		if (const auto injectorListener = mInjectorListener.lock()) {
			injectorListener->inject(branch->extractRequest(), shared_from_this(), contact->contactId());
		} else {
			mAgent->injectRequest(branch->extractRequest());
		}
	}

	return branch;
}

void ForkContextImpl::onNextBranches() {
	if (hasNextBranches()) start();
}

bool ForkContextImpl::hasNextBranches() const {
	const auto hasWaitingBranchesLeft =
	    any_of(mWaitingBranches.cbegin(), mWaitingBranches.cend(),
	           [this](const auto& br) { return mCurrentPriority == -1.f || br->getPriority() < mCurrentPriority; });
	return !mFinished && hasWaitingBranchesLeft && mStrategy->shouldAcceptNextBranches();
}

void ForkContextImpl::nextBranches() {
	// Clear all current branches if there is any.
	mCurrentBranches.clear();

	// Get next priority value.
	if (mCurrentPriority == -1.f && !mWaitingBranches.empty()) {
		mCurrentPriority = mWaitingBranches.front()->getPriority();
	} else {
		for (const auto& br : mWaitingBranches) {
			if (br->getPriority() < mCurrentPriority) {
				mCurrentPriority = br->getPriority();
				break;
			}
		}
	}

	// Store all wanted branches.
	for (const auto& br : mWaitingBranches)
		if (br->getPriority() == mCurrentPriority) mCurrentBranches.push_back(br);
}

void ForkContextImpl::start() {
	if (mFinished) {
		LOGE << "Calling start() on a finished fork: do nothing";
		return;
	}

	// hack for voicemail
	mStrategy->setForkContext(shared_from_this());

	bool firstStart = mCurrentPriority == -1.f;
	if (firstStart) {
		// We want all the branches in the event, so that presumes there are no branches answered yet. We also presume
		// all branches have been added by now.
		auto& event = getEvent();
		if (auto eventLog = mStrategy->makeStartEventLog(*event.getMsgSip(), mWaitingBranches))
			event.writeLog(eventLog);
	}

	// Remove existing timer.
	mNextBranchesTimer.stop();

	// Prepare branches.
	nextBranches();

	LOGD << "Started forking branches with priority '" << mCurrentPriority << "'";

	// Start the processing.
	for (const auto& br : mCurrentBranches) {
		if (const auto injectorListener = mInjectorListener.lock()) {
			injectorListener->inject(br->extractRequest(), shared_from_this(), br->getContact()->contactId());
		} else {
			mAgent->injectRequest(br->extractRequest());
		}

		// Can only occur if an internal error append
		if (mCurrentBranches.empty()) break;
	}

	// Start the timer for the next branches.
	if (mCfg->mCurrentBranchesTimeout > 0s && hasNextBranches())
		mNextBranchesTimer.set(
		    [this] {
			    LOGD << "Timer 'call-fork-current-branches-timeout' triggered";
			    onNextBranches();
		    },
		    mCfg->mCurrentBranchesTimeout);
}

RequestSipEvent& ForkContextImpl::getEvent() {
	return *mEvent;
}

sofiasip::MsgSipPriority ForkContextImpl::getMsgPriority() const {
	return mMsgPriority;
}

const std::shared_ptr<ForkContextConfig>& ForkContextImpl::getConfig() const {
	return mCfg;
}

const std::shared_ptr<IncomingTransaction>& ForkContextImpl::getIncomingTransaction() const {
	return mIncoming;
}

void ForkContextImpl::onFinished() {
	if (const auto forkContextListener = mForkContextListener.lock()) {
		forkContextListener->onForkContextFinished(shared_from_this());
	} else {
		LOGE << "Failed to notify ForkContextListener that fork is finished (std::weak_ptr of listener is empty)";
	}
}

void ForkContextImpl::setFinished() {
	// Already finishing: ignore.
	if (mFinishTimer.isRunning()) return;

	mFinished = true;

	mLateTimer.stop();
	mNextBranchesTimer.stop();
	mFinishTimer.set(
	    [weak = weak_ptr{shared_from_this()}] {
		    if (const auto shared = weak.lock()) shared->onFinished();
	    },
	    0ms);
}

bool ForkContextImpl::shouldFinish(bool ignoreForkLate) {
	return (ignoreForkLate || !mCfg->mForkLate) && (!mIncoming || mStrategy->shouldFinish());
}

std::unique_ptr<ResponseSipEvent> ForkContextImpl::onSendResponse(std::unique_ptr<ResponseSipEvent>&& event) {
	if (!mIncoming) return {};

	const int code = event->getStatusCode();
	event->setIncomingAgent(mIncoming);
	mLastResponseSent = event->getMsgSip();

	if (event->isSuspended()) event = mAgent->injectResponse(std::move(event));
	else event = mAgent->processResponse(std::move(event));

	if (code >= 200) {
		mIncoming.reset();
		mNextBranchesTimer.stop();
		if (shouldFinish()) setFinished();
	}

	return std::move(event);
}

void ForkContextImpl::onCancel(const MsgSip& ms) {
	mStrategy->onCancel(ms);
	for (const auto& br : mWaitingBranches) {
		mStrategy->updateBranch(br, getEvent());
	}
	if (shouldFinish()) setFinished();
	else tryToSendFinalResponse();
	if (mIncoming) {
		if (auto branch = findBestBranch(false)) {
			branch->sendResponse(mIncoming != nullptr);
			mStrategy->logSentResponse(branch->getLastResponseEvent(), branch.get(), getEvent());
		}
	}
	mNextBranchesTimer.stop();
}

void ForkContextImpl::onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) {
	if (br->getStatus() >= 200) br->notifyBranchCompleted();

	mStrategy->logResponse(br, getEvent(), ev);
	const auto action = mStrategy->chooseActionOnResponse(br);
	LOGD << "Received " << br->getStatus() << ", " << onResponseActionToString(action);

	if (action == OnResponseAction::Send || action == OnResponseAction::SendAndUpdate) {
		br->sendResponse(mIncoming != nullptr);
		mStrategy->logSentResponse(br->getLastResponseEvent(), br.get(), getEvent());
	}
	if (action == OnResponseAction::WaitAndUpdate || action == OnResponseAction::SendAndUpdate) {
		for (const auto& branch : mWaitingBranches) {
			mStrategy->updateBranch(branch, getEvent());
		}
	}
	tryToSendFinalResponse();
}

void ForkContextImpl::onNewRegister(const SipUri& dest,
                                    const std::string& uid,
                                    const std::shared_ptr<ExtendedContact>& newContact) {
	const auto forkContextListener = mForkContextListener.lock();
	if (!forkContextListener) {
		LOGE << "ForkContextListener is missing, cannot process new register (this should not happen)";
		return;
	}

	if (!mStrategy->mayAcceptNewRegister(dest, uid, newContact)) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
		                                                   DispatchStatus::DispatchNotNeeded);
		return;
	}

	const auto [status, branch] = shouldDispatch(dest, uid);
	// check branch
	if (status != DispatchStatus::DispatchNeeded || !mStrategy->shouldAcceptDispatch(branch, uid)) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, status);
		return;
	}
	auto dispatchedBranch = forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
	if (dispatchedBranch) {
		mStrategy->onDispatch(dispatchedBranch);
		tryToSendFinalResponse();
	}
}

bool ForkContextImpl::isFinished() const {
	return mFinished;
}

void ForkContextImpl::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	if (m110Sent) return;

	sendResponse(110, "Push sent", aPNCtx.toTagEnabled());
	m110Sent = true;
	if (aRingingPush && !isRingingSomewhere()) sendResponse(180, sip_180_Ringing, aPNCtx.toTagEnabled());
}

void ForkContextImpl::addKey(const string& key) {
	mKeys.push_back(key);
}

const vector<string>& ForkContextImpl::getKeys() const {
	return mKeys;
}

int ForkContextImpl::getLastResponseCode() const {
	if (!mLastResponseSent) return 0;

	return mLastResponseSent->getSip()->sip_status->st_status;
}

unique_ptr<ResponseSipEvent> ForkContextImpl::sendCustomResponse(int status, const char* phrase) {
	if (!mIncoming) {
		LOGD << "Cannot send SIP response [" << status << " " << phrase << "]: no incoming transaction";
		return {};
	}

	const auto message = mIncoming->createResponse(status, phrase);
	if (message == nullptr) { // Should never happen
		LOGE << "Error, MsgSip cannot be created: fork is completed without sending any response";
		setFinished();
		return {};
	}

	auto ev = make_unique<ResponseSipEvent>(mAgent->getOutgoingAgent(), message);
	return onSendResponse(std::move(ev));
}

void ForkContextImpl::processInternalError(int status, const char* phrase) {
	sendCustomResponse(status, phrase);
	mStrategy->onInternalError();
	for (const auto& br : mWaitingBranches) {
		mStrategy->updateBranch(br, getEvent());
	}
}

void ForkContextImpl::tryToSendFinalResponse() {
	if (!mIncoming && shouldFinish()) {
		setFinished();
		return;
	}
	if (!allBranchesAnswered(FinalStatusMode::RFC)) return;

	if (shouldFinish() || (shouldFinish(true) && allBranchesAnswered(FinalStatusMode::ForkLate))) setFinished();

	auto best = findBestBranch(mCfg->mForkLate);
	const auto respStrategy =
	    best && isFinished() ? ResponseStrategy::Best : mStrategy->chooseStrategyOnceAllBranchesAnswered(best);
	applyResponseStrategy(respStrategy);
}

void ForkContextImpl::applyResponseStrategy(ResponseStrategy respStrategy) {
	if (!mIncoming) return;

	auto branch = findBestBranch(mCfg->mForkLate);
	switch (respStrategy) {
		case ResponseStrategy::BestElseDefault:
		case ResponseStrategy::Best: {
			if (branch != nullptr && branch->getStatus() >= 200) {
				branch->sendResponse(mIncoming != nullptr);
				mStrategy->logSentResponse(branch->getLastResponseEvent(), branch.get(), getEvent());
				break;
			}
			if (respStrategy == ResponseStrategy::Best) break;
			[[fallthrough]];
		}
		case ResponseStrategy::Default: {
			if (const auto [code, phrase] = mStrategy->getDefaultResponse(); code != 0)
				mStrategy->logSentResponse(sendCustomResponse(code, phrase), nullptr, getEvent());
			break;
		}
		default:
			break;
	}
}

const ForkContext* ForkContextImpl::getPtrForEquality() const {
	return this;
}

bool ForkContextImpl::isRingingSomewhere() const {
	return any_of(mWaitingBranches.cbegin(), mWaitingBranches.cend(), [](const auto& br) {
		const auto status = br->getStatus();
		return status >= 180 && status < 200;
	});
}