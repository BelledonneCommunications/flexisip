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

#include "fork-message-context-db-proxy.hh"

#include "fork-message-context-soci-repository.hh"
#include "utils/thread/auto-thread-pool.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace {
unsigned int getMaxThreadNumber(const ConfigManager& cfg) {
	const auto* routerConf = cfg.getRoot()->get<GenericStruct>("module::Router");
	return routerConf->get<ConfigInt>("message-database-pool-size")->read() * 2;
}
} // namespace

std::shared_ptr<ForkMessageContextDbProxy> ForkMessageContextDbProxy::make(const shared_ptr<ModuleRouter>& router,
                                                                           unique_ptr<RequestSipEvent>&& event,
                                                                           sofiasip::MsgSipPriority priority) {
	// new because make_shared require a public constructor.
	shared_ptr<ForkMessageContextDbProxy> shared{new ForkMessageContextDbProxy(router, priority)};

	shared->mForkMessage = ForkMessageContext::make(router, shared, std::move(event), priority);

	return shared;
}

shared_ptr<ForkMessageContextDbProxy> ForkMessageContextDbProxy::make(const shared_ptr<ModuleRouter>& router,
                                                                      ForkMessageContextDb& forkFromDb) {
	// new because make_shared require a public constructor.
	shared_ptr<ForkMessageContextDbProxy> shared{new ForkMessageContextDbProxy(router, forkFromDb)};

	shared->startTimerAndResetFork(timegm(&forkFromDb.expirationDate), forkFromDb.dbKeys);

	return shared;
}

ForkMessageContextDbProxy::ForkMessageContextDbProxy(const std::shared_ptr<ModuleRouter> router,
                                                     sofiasip::MsgSipPriority priority)
    : mForkMessage{}, mState{State::IN_MEMORY}, mProxyLateTimer{router->getAgent()->getRoot()},
      mCounter{router->mStats.mCountMessageProxyForks}, mSavedRouter{router}, mSavedConfig{router->getMessageForkCfg()},
      mSavedMsgPriority{priority}, mMaxThreadNumber{getMaxThreadNumber(router->getAgent()->getConfigManager())},
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "ForkMessageContextDbProxy")} {
	LOGD << "New instance";
	if (auto sharedCounter = mCounter.lock()) {
		sharedCounter->incrStart();
	} else {
		LOGE << "Fork error: weak_ptr mCounter should be present here";
	}
}

ForkMessageContextDbProxy::ForkMessageContextDbProxy(const std::shared_ptr<ModuleRouter> router,
                                                     ForkMessageContextDb& forkFromDb)
    : ForkMessageContextDbProxy(router, forkFromDb.msgPriority) {

	mForkUuidInDb = forkFromDb.uuid;
	mLastSavedVersion = mCurrentVersion.load();
	setState(State::IN_DATABASE);
}

ForkMessageContextDbProxy::~ForkMessageContextDbProxy() {
	LOGD << "Destroy instance";
	if (auto sharedCounter = mCounter.lock()) {
		sharedCounter->incrFinish();
	} else {
		LOGE << "Fork error: weak_ptr mCounter should be present here";
	}

	if (!mForkUuidInDb.empty() && mIsFinished) {
		// Destructor is called because the ForkContext is finished, removing info from database
		LOGD << "Was present in database, cleaning UUID [" << mForkUuidInDb << "]";
		AutoThreadPool::getDbThreadPool(mMaxThreadNumber)->run([uuid = mForkUuidInDb]() {
			ForkMessageContextSociRepository::getInstance()->deleteByUuid(uuid);
		});
	}
}

void ForkMessageContextDbProxy::loadFromDb() const {
	LOGD << "Retrieving message in database for UUID [" << mForkUuidInDb << "]";
	mDbFork = make_unique<ForkMessageContextDb>(
	    ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(mForkUuidInDb));
}

bool ForkMessageContextDbProxy::saveToDb(const ForkMessageContextDb& dbFork) {
	LOGD << "Saving ForkMessage to DB";
	try {
		if (mForkUuidInDb.empty()) {
			LOGD << "Not saved before, creating a new entry";
			mForkUuidInDb = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(dbFork);
		} else {
			LOGD << "Already in database with UUID [" << mForkUuidInDb << "], updating";
			ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(dbFork, mForkUuidInDb);
		}
		if (mForkUuidInDb.empty()) {
			LOGE << "Fork error: mForkUuidInDb empty after save, keeping message in memory";
			return false;
		}
	} catch (const exception& e) {
		LOGE << "A problem occurred while saving ForkMessageContext, it will remain in RAM: " << e.what();
		return false;
	}
	return true;
}

void ForkMessageContextDbProxy::onForkContextFinished([[maybe_unused]] const shared_ptr<ForkContext>& ctx) {
	LOGD << "Running " << __func__;
	mIsFinished = true;
	if (auto savedRouter = mSavedRouter.lock()) {
		savedRouter->onForkContextFinished(shared_from_this());
	} else {
		LOGE << "Fork error: weak_ptr mSavedRouter should be present here (onForkContextFinished)";
	}
}

std::shared_ptr<BranchInfo>
ForkMessageContextDbProxy::onDispatchNeeded([[maybe_unused]] const shared_ptr<ForkContext>& ctx,
                                            const shared_ptr<ExtendedContact>& newContact) {
	if (auto savedRouter = mSavedRouter.lock()) {
		mCurrentVersion++;
		return savedRouter->onDispatchNeeded(shared_from_this(), newContact);
	} else {
		LOGE << "Fork error: weak_ptr mSavedRouter should be present here (onDispatchNeeded)";
		return nullptr;
	}
}

void ForkMessageContextDbProxy::onUselessRegisterNotification([[maybe_unused]] const std::shared_ptr<ForkContext>& ctx,
                                                              const std::shared_ptr<ExtendedContact>& newContact,
                                                              const SipUri& dest,
                                                              const std::string& uid,
                                                              const DispatchStatus reason) {
	clearMemoryIfPossible();

	/*
	 * If reason == DispatchStatus::PendingTransaction the transaction may or may not be successful in the future,
	 * so we need to wait before storing this destination as already delivered.
	 */
	if (reason != DispatchStatus::PendingTransaction) {
		mAlreadyDelivered.emplace(dest.getHost(), dest.getPort(), uid);
	}

	if (auto savedRouter = mSavedRouter.lock()) {
		savedRouter->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, reason);
	} else {
		LOGE << "Fork error: weak_ptr mSavedRouter should be present here (onUselessRegisterNotification)";
	}
}

void ForkMessageContextDbProxy::runSavingThread() {
	const auto dbFork = mForkMessage->getDbObject();
	AutoThreadPool::getDbThreadPool(mMaxThreadNumber)
	    ->run([thiz = shared_from_this(), dbFork, dbForkVersion = mCurrentVersion.load()]() {
		    lock_guard<mutex> lock(thiz->mDbAccessMutex);
		    if (dbForkVersion == thiz->mCurrentVersion && thiz->mLastSavedVersion < dbForkVersion &&
		        thiz->saveToDb(dbFork)) {
			    thiz->mLastSavedVersion = dbForkVersion;

			    if (auto router = thiz->mSavedRouter.lock()) {
				    router->getAgent()->getRoot()->addToMainLoop(
				        [weak = weak_ptr<ForkMessageContextDbProxy>{thiz->shared_from_this()}]() {
					        if (auto shared = weak.lock()) {
						        shared->clearMemoryIfPossible();
					        }
				        });
			    }
		    }
	    });
}

void ForkMessageContextDbProxy::onResponse(const shared_ptr<BranchInfo>& br, ResponseSipEvent& event) {
	LOGD << "Running " << __func__;
	checkState(__FUNCTION__, State::IN_MEMORY);

	mForkMessage->onResponse(br, event);

	if (canBeSaved()) {
		runSavingThread();
	}
}

void ForkMessageContextDbProxy::onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept {
	// Not using checkState() here because onPushSent() may be called whatever the state of the proxy.
	// If the ForkMessageContext is already in database when the PN is sent, then no need to restore it
	// because the incoming transaction is closed anyway and the “110 Push sent” response cannot be sent.
	// If the ForkMessageContext is in memory, then the event is forwarded to it and “110 Push sent” response
	// is sent depending whether the incoming transaction is still current.
	lock_guard<recursive_mutex> _{mStateMutex};
	if (mState == State::IN_MEMORY) {
		mForkMessage->onPushSent(aPNCtx, aRingingPush);
	}
}

void ForkMessageContextDbProxy::onNewRegister(const SipUri& dest,
                                              const std::string& uid,
                                              const std::shared_ptr<ExtendedContact>& newContact) {
	LOGD << "Running " << __func__;
	const auto& sharedRouter = mSavedRouter.lock();
	if (!sharedRouter) {
		LOGE << "Router missing, this should not happen";
		return;
	}

	// Do not access DB or call OnNewRegister if we already know that this device is delivered.
	if (isAlreadyDelivered(dest, uid)) {
		sharedRouter->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
		                                            DispatchStatus::DispatchNotNeeded);
		return;
	}

	// Try to restore the ForkMessage from a previous recursive call.
	if (!restoreForkIfNeeded()) { // runtime_error during restoration
		sharedRouter->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
		                                            DispatchStatus::DispatchNotNeeded);
		return;
	}

	// If the ForkMessage is only in database create a thread to access database and then recursively call this method.
	if (getState() == State::IN_DATABASE) {
		LOGD << "Message is in database, initiating load";
		AutoThreadPool::getDbThreadPool(mMaxThreadNumber)->run([thiz = shared_from_this(), dest, uid, newContact]() {
			lock_guard<mutex> lock(thiz->mDbAccessMutex);
			if (thiz->getState() == State::IN_DATABASE && !thiz->mDbFork) {
				try {
					thiz->loadFromDb();
				} catch (const exception& e) {
					LOGE_CTX(thiz->mLogPrefix, "onNewRegister")
					    << "Error loading ForkMessageContext from database: " << e.what();
				}
			} else {
				LOGD_CTX(thiz->mLogPrefix, "onNewRegister") << "Message was previously loaded (thread)";
			}

			if (auto router = thiz->mSavedRouter.lock()) {
				LOGD_CTX(thiz->mLogPrefix, "onNewRegister")
				    << "Loaded or previously loaded, recursively added to main loop (thread)";
				router->getAgent()->getRoot()->addToMainLoop(
				    [weak = weak_ptr<ForkMessageContextDbProxy>{thiz->shared_from_this()}, dest, uid, newContact]() {
					    if (auto shared = weak.lock()) {
						    shared->onNewRegister(dest, uid, newContact);
					    }
				    });
			} else {
				LOGE_CTX(thiz->mLogPrefix, "onNewRegister") << "Router missing, this should not happen";
			}
		});

		return;
	}

	// Call the reel OnNewRegister method on the proxified object.
	mForkMessage->onNewRegister(dest, uid, newContact);
}

bool ForkMessageContextDbProxy::canBeSaved() const {
	return getState() == State::IN_MEMORY && mForkMessage->allBranchesAnswered(FinalStatusMode::RFC) &&
	       !mForkMessage->isFinished();
}

void ForkMessageContextDbProxy::clearMemoryIfPossible() {
	if (mLastSavedVersion == mCurrentVersion && canBeSaved()) {
		setState(State::IN_DATABASE);
		startTimerAndResetFork();
	}
}

bool ForkMessageContextDbProxy::isAlreadyDelivered(const SipUri& uri, const string& uid) {
	const auto host = uri.getHost();
	const auto port = uri.getPort();
	return any_of(mAlreadyDelivered.begin(), mAlreadyDelivered.end(),
	              [&](const std::tuple<std::string, std::string, std::string>& item) {
		              const auto& itemUid = get<2>(item);
		              if (!uid.empty() || !itemUid.empty()) {
			              return uid == itemUid;
		              } else {
			              return host == get<0>(item) && port == get<1>(item);
		              }
	              });
}

bool ForkMessageContextDbProxy::restoreForkIfNeeded() {
	if (mDbFork) {
		try {
			if (auto router = mSavedRouter.lock()) {
				mForkMessage = ForkMessageContext::make(router, shared_from_this(), *mDbFork);
			} else {
				return false;
			}
			mDbFork.reset();

			// Timer is now handle by the newly restored inner ForkMessageContext
			mProxyLateTimer.reset();
			setState(State::IN_MEMORY);
		} catch (const runtime_error& e) {
			LOGE << "An error occurred during ForkMessage creation from database object with UUID [" << mForkUuidInDb
			     << "]: " << e.what();

			mForkMessage.reset();
			setState(State::IN_DATABASE);
			onForkContextFinished(nullptr);
			return false;
		}
	}
	return true;
}

void ForkMessageContextDbProxy::checkState(const string& methodName,
                                           const ForkMessageContextDbProxy::State& expectedState) const {
	lock_guard<recursive_mutex> lock(mStateMutex);
	if (mState != expectedState) {
		stringstream ss;
		LOGE << "Bad state: actual [" << mState << "], expected [" << expectedState << "] in " << methodName;
		throw logic_error{ss.str()};
	}
}

void ForkMessageContextDbProxy::startTimerAndResetFork(time_t expirationDate, const vector<string>& keys) {
	// We need to handle fork late timer in proxy object in case it expires while inner object is still in database.
	auto diff = system_clock::from_time_t(expirationDate) - system_clock::now();
	if (diff < 0s) diff = 0s;

	LOGD << "Expiration in: " << duration_cast<seconds>(diff).count() << "s";

	mProxyLateTimer.set(
	    [weak = weak_ptr<ForkMessageContextDbProxy>{shared_from_this()}]() {
		    if (auto shared = weak.lock()) {
			    shared->onForkContextFinished(nullptr);
		    }
	    },
	    diff);

	// If timer expire while ForkMessage is still in DB we need to keep track of keys to remove proxy from Fork list.
	mSavedKeys = vector<string>{keys};

	mForkMessage.reset();
}

void ForkMessageContextDbProxy::startTimerAndResetFork() {
	startTimerAndResetFork(mForkMessage->getExpirationDate(), mForkMessage->getKeys());
}

ForkMessageContextDbProxy::State ForkMessageContextDbProxy::getState() const {
	lock_guard<recursive_mutex> lock(mStateMutex);
	return mState;
}

void ForkMessageContextDbProxy::setState(ForkMessageContextDbProxy::State state) {
	lock_guard<recursive_mutex> lock(mStateMutex);
	mState = state;
}

ostream& operator<<(ostream& os, flexisip::ForkMessageContextDbProxy::State state) noexcept {
	switch (state) {
		case flexisip::ForkMessageContextDbProxy::State::IN_DATABASE:
			return os << "IN_DATABASE";
		case flexisip::ForkMessageContextDbProxy::State::IN_MEMORY:
			return os << "IN_MEMORY";
	}
	return os << "Unknown";
}

} // namespace flexisip