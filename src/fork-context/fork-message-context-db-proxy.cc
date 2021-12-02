/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/fork-context/fork-message-context-db-proxy.hh"

using namespace std;

namespace flexisip {

shared_ptr<ForkMessageContextDbProxy> ForkMessageContextDbProxy::make(Agent* agent,
                                                                      const shared_ptr<RequestSipEvent>& event,
                                                                      const shared_ptr<ForkContextConfig>& cfg,
                                                                      const weak_ptr<ForkContextListener>& listener,
                                                                      const weak_ptr<StatPair>& messageCounter,
                                                                      const weak_ptr<StatPair>& proxyCounter) {

	SLOGD << "Make ForkMessageContextDbProxy";
	// new because make_shared require a public constructor.
	const shared_ptr<ForkMessageContextDbProxy> shared{
	    new ForkMessageContextDbProxy(agent, event, cfg, listener, messageCounter, proxyCounter)};

	shared->mForkMessage = ForkMessageContext::make(agent, event, cfg, shared, messageCounter, true);

	return shared;
}

shared_ptr<ForkMessageContextDbProxy> ForkMessageContextDbProxy::make(Agent* agent,
                                                                      const shared_ptr<RequestSipEvent>& event,
                                                                      const shared_ptr<ForkContextConfig>& cfg,
                                                                      const weak_ptr<ForkContextListener>& listener,
                                                                      const weak_ptr<StatPair>& messageCounter,
                                                                      const weak_ptr<StatPair>& proxyCounter,
                                                                      ForkMessageContextDb& forkFromDb) {
	SLOGD << "Make ForkMessageContextDbProxy from a restored message";
	// new because make_shared require a public constructor.
	const shared_ptr<ForkMessageContextDbProxy> shared{
	    new ForkMessageContextDbProxy(agent, event, cfg, listener, messageCounter, proxyCounter)};

	shared->mForkUuidInDb = forkFromDb.uuid;
	shared->mState = State::IN_DATABASE;

	return shared;
}

ForkMessageContextDbProxy::ForkMessageContextDbProxy(Agent* agent,
                                                     const shared_ptr<RequestSipEvent>& event,
                                                     const shared_ptr<ForkContextConfig>& cfg,
                                                     const weak_ptr<ForkContextListener>& listener,
                                                     const weak_ptr<StatPair>& messageCounter,
                                                     const weak_ptr<StatPair>& proxyCounter)
    : mForkMessage{}, mState{State::IN_MEMORY}, mProxyLateTimer{agent->getRoot()},
      mOriginListener{listener}, mCounter{proxyCounter},
      savedAgent(agent), savedRequest{event}, savedConfig{cfg}, savedCounter{messageCounter} {

	LOGD("New ForkMessageContextDbProxy %p", this);
	if (auto sharedCounter = mCounter.lock()) {
		sharedCounter->incrStart();
	}
}

ForkMessageContextDbProxy::~ForkMessageContextDbProxy() {
	LOGD("Destroy ForkMessageContextDbProxy %p", this);
	if (auto sharedCounter = mCounter.lock()) {
		sharedCounter->incrFinish();
	}

	if (mForkMessage && !mForkMessage->isFinished()) {
		// Should be shutting down the server save everything you can.
		saveToDb();
	} else if (!mForkUuidInDb.empty()) {
		// Destructor is called because the ForkContext is finished, removing info from database
		LOGD("ForkMessageContextDbProxy[%p] was present in DB, cleaning UUID[%s]", this, mForkUuidInDb.c_str());
		ForkMessageContextSociRepository::getInstance()->deleteByUuid(mForkUuidInDb);
	}
}

void ForkMessageContextDbProxy::loadFromDb() const {
	LOGI("ForkMessageContextDbProxy[%p] retrieving message in DB for UUID [%s]", this, mForkUuidInDb.c_str());
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(mForkUuidInDb);
	// loadFromDb() need to stay const (mForkMessage is mutable) but we need a non const shared_ptr
	auto nonConstShared = const_pointer_cast<ForkMessageContextDbProxy>(shared_from_this());
	mForkMessage =
	    ForkMessageContext::make(savedAgent, savedRequest, savedConfig, nonConstShared, savedCounter, dbFork);
	// Timer is now handle by the newly restored inner ForkMessageContext
	mProxyLateTimer.reset();
}

bool ForkMessageContextDbProxy::saveToDb() {
	LOGI("ForkMessageContextDbProxy[%p] saving ForkMessage to DB.", this);
	try {
		if (mForkUuidInDb.empty()) {
			LOGD("ForkMessageContextDbProxy[%p] not saved before, creating a new entry.", this);
			mForkUuidInDb = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(mForkMessage);
		} else {
			LOGD("ForkMessageContextDbProxy[%p] already in DB with UUID[%s], updating", this, mForkUuidInDb.c_str());
			ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(mForkMessage, mForkUuidInDb);
		}
		// Do not reset mForkMessage directly in a thread
		savedAgent->getRoot()->addToMainLoop([this]() { startTimerAndResetFork(); });
	} catch (const exception& e) {
		SLOGE << "A problem occurred during ForkMessageContext saving, it will remain in memory : " << e.what();
		return false;
	}
	return true;
}

void ForkMessageContextDbProxy::onForkContextFinished(const shared_ptr<ForkContext>& ctx) {
	if (auto originListener = mOriginListener.lock()) {
		originListener->onForkContextFinished(shared_from_this());
	}
}

void ForkMessageContextDbProxy::onResponse(const shared_ptr<BranchInfo>& br,
                                           const shared_ptr<ResponseSipEvent>& event) {
	LOGD("ForkMessageContextDbProxy[%p] onResponse", this);
	checkState(__FUNCTION__, State::IN_MEMORY);

	mForkMessage->onResponse(br, event);

	if (mForkMessage->allBranchesAnswered() && !mForkMessage->isFinished()) {
		mState = State::SAVING;
		thread savingThread([this]() {
			lock_guard<mutex> lock(mMutex);
			if(mState == State::IN_DATABASE) {
				return;
			}
			if(!saveToDb()) {
				mState = State::IN_MEMORY;
			}
		  	mState = State::IN_DATABASE;
		});
		savingThread.detach();
	}
}

bool ForkMessageContextDbProxy::onNewRegister(const SipUri& dest,
                                              const string& uid,
                                              const function<void()>& dispatchFunc) {

	if (mState != State::IN_MEMORY) {
		thread restoringThread([this, dest, uid, dispatchFunc]() {
			// If multiples onNewRegister are active at the same time on one ForkMessage only one should access DB
			// at the same time
			lock_guard<mutex> lock(mMutex);
			if (mState != State::IN_MEMORY) {
				checkState("restoringThread exec", State::IN_DATABASE);
				mState = State::RESTORING;
				try {
					loadFromDb();
				} catch (const exception& e) {
					SLOGE << "Error loading ForkMessageContext from db : " << e.what();
					mState = State::IN_DATABASE;
					// Returning cancel the onNewRegister process but the user can still receive the message with his
					// next register.
					return;
				}
				mState = State::IN_MEMORY;
			}
			savedAgent->getRoot()->addToMainLoop(
			    [this, dest, uid, dispatchFunc]() { mForkMessage->onNewRegister(dest, uid, dispatchFunc); });
		});
		restoringThread.detach();

		// This return value is never used and ,for now, arbitrary
		return true;
	} else {
		return mForkMessage->onNewRegister(dest, uid, dispatchFunc);
	}
}

void ForkMessageContextDbProxy::checkState(const string& methodName,
                                           const ForkMessageContextDbProxy::State& expectedState) const {
	if (mState != expectedState) {
		stringstream ss;
		ss << "Bad ForkMessageContextDbProxy state :  actual [" << mState << "] expected [" << expectedState << "] in "
		   << methodName;
		SLOGE << ss.str();
		throw logic_error{ss.str()};
	}
}

void ForkMessageContextDbProxy::startTimerAndResetFork() {
	LOGD("ForkMessageContextDbProxy[%p] startTimerAndResetFork", this);
	// We need to handle fork late timer in proxy object in case it expire while inner object is still in database.
	const auto utcNow = time(nullptr);
	auto timeout = difftime(mForkMessage->getExpirationDate() , utcNow);
	mProxyLateTimer.set([this]() { onForkContextFinished(nullptr); }, timeout * 1000);

	mForkMessage.reset();
}

ostream& operator<<(ostream& os, flexisip::ForkMessageContextDbProxy::State state) noexcept {
	switch (state) {
		case flexisip::ForkMessageContextDbProxy::State::IN_DATABASE:
			return os << "In database";
		case flexisip::ForkMessageContextDbProxy::State::IN_MEMORY:
			return os << "In memory";
		case flexisip::ForkMessageContextDbProxy::State::SAVING:
			return os << "Saving";
		case flexisip::ForkMessageContextDbProxy::State::RESTORING:
			return os << "Restoring";
	};
	return os << "Unknown";
}

} // namespace flexisip