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

#include "fork-context-factory.hh"
#include "fork-message-context-soci-repository.hh"
#include "router/fork-manager.hh"
#include "utils/thread/auto-thread-pool.hh"

using namespace std;
using namespace std::chrono;

namespace flexisip {
namespace {

unsigned int getMaxThreadNumber(const ConfigManager& cfg) {
	const auto* routerConf = cfg.getRoot()->getModuleSectionByRole("Router");
	return routerConf->get<ConfigInt>("message-database-pool-size")->read() * 2;
}

} // namespace

ForkMessageContextDbProxy::ForkMessageContextDbProxy(std::unique_ptr<RequestSipEvent>&& event,
                                                     sofiasip::MsgSipPriority priority,
                                                     bool isRestored,
                                                     const std::weak_ptr<ForkContextListener>& forkContextListener,
                                                     const std::weak_ptr<InjectorListener>& injectorListener,
                                                     const std::weak_ptr<ForkMessageContextSociRepository>& database,
                                                     Agent* agent,
                                                     const std::shared_ptr<ForkContextConfig>& config,
                                                     const std::weak_ptr<StatPair>& forkMessageCounter,
                                                     const std::weak_ptr<StatPair>& counter)
    : mAgent(agent), mState{State::IN_MEMORY}, mProxyLateTimer{agent->getRoot()}, mCounter{counter},
      mForkContextListener{forkContextListener}, mSavedConfig{config}, mSavedMsgPriority{priority},
      mMaxThreadNumber{getMaxThreadNumber(agent->getConfigManager())}, mForkMessageDatabase{database},
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "ForkMessageContextDbProxy")} {
	LOGD << "New instance";
	if (const auto statCounter = mCounter.lock()) {
		statCounter->incrStart();
	} else {
		LOGE << "Failed to increment counter 'count-message-proxy-forks' (std::weak_ptr is empty)";
	}

	if (event != nullptr)
		mForkMessage =
		    ForkMessageContext::make(std::move(event), priority, MessageKind{*event->getSip(), priority}, isRestored,
		                             forkContextListener, injectorListener, agent, config, forkMessageCounter);
}

std::shared_ptr<ForkMessageContextDbProxy>
ForkMessageContextDbProxy::restore(ForkMessageContextDb& forkContextFromDb,
                                   const std::weak_ptr<ForkContextListener>& forkContextListener,
                                   const std::weak_ptr<InjectorListener>& injectorListener,
                                   const std::weak_ptr<ForkMessageContextSociRepository>& database,
                                   Agent* agent,
                                   const std::shared_ptr<ForkContextConfig>& config,
                                   const std::weak_ptr<StatPair>& forkMessageCounter,
                                   const std::weak_ptr<StatPair>& counter) {

	const auto context = make(nullptr, forkContextFromDb.msgPriority, true, forkContextListener, injectorListener,
	                          database, agent, config, forkMessageCounter, counter);

	context->mForkUuidInDb = forkContextFromDb.uuid;
	context->mLastSavedVersion = context->mCurrentVersion.load();
	context->setState(State::IN_DATABASE);
	context->startTimerAndResetFork(timegm(&forkContextFromDb.expirationDate), forkContextFromDb.dbKeys);

	return context;
}

ForkMessageContextDbProxy::~ForkMessageContextDbProxy() {
	LOGD << "Destroy instance";
	if (const auto statCounter = mCounter.lock()) {
		statCounter->incrFinish();
	} else {
		LOGE << "Failed to increment counter 'count-message-proxy-forks-finished' (std::weak_ptr is empty)";
	}

	if (!mForkUuidInDb.empty() && mIsFinished) {
		// Destructor is called because the ForkContext is finished, removing info from the database.
		LOGD << "Was present in database, removing UUID [" << mForkUuidInDb << "] from the database";
		AutoThreadPool::getDbThreadPool(mMaxThreadNumber)
		    ->run([uuid = mForkUuidInDb, database = mForkMessageDatabase.lock(), prefix = mLogPrefix] {
			    if (database) database->deleteByUuid(uuid);
			    else LOGE_CTX(prefix) << "Access to database unavailable (ForkMessageContextSociRepository is nullptr)";
		    });
	}
}

void ForkMessageContextDbProxy::loadFromDb() const {
	LOGD << "Retrieving message in database for UUID [" << mForkUuidInDb << "]";
	const auto database = mForkMessageDatabase.lock();
	if (database == nullptr) {
		LOGE << "Access to database unavailable (ForkMessageContextSociRepository is nullptr)";
		return;
	}

	mDbFork = make_unique<ForkMessageContextDb>(database->findForkMessageByUuid(mForkUuidInDb));
}

bool ForkMessageContextDbProxy::saveToDb(const ForkMessageContextDb& dbFork) {
	LOGD << "Saving to database";
	const auto database = mForkMessageDatabase.lock();
	if (database == nullptr) {
		SLOGE << "Access to database unavailable (ForkMessageContextSociRepository is nullptr)";
		return false;
	}

	try {
		if (mForkUuidInDb.empty()) {
			LOGD << "Not saved before, creating a new entry";
			mForkUuidInDb = database->saveForkMessageContext(dbFork);
			LOGD << "Successfully saved with UUID [" << mForkUuidInDb << "]";
		} else {
			LOGD << "Already in database with UUID [" << mForkUuidInDb << "], updating";
			database->updateForkMessageContext(dbFork, mForkUuidInDb);
		}
		if (mForkUuidInDb.empty()) {
			LOGE << "Error: no UUID returned after attempting to save into the database, keeping message in memory";
			return false;
		}
	} catch (const exception& e) {
		LOGE << "A problem occurred while saving, it will remain in memory: " << e.what();
		return false;
	}
	return true;
}

void ForkMessageContextDbProxy::onForkContextFinished([[maybe_unused]] const shared_ptr<ForkContext>& ctx) {
	LOGD << "Running " << __func__;
	mIsFinished = true;
	if (const auto forkContextListener = mForkContextListener.lock()) {
		forkContextListener->onForkContextFinished(shared_from_this());
	} else {
		LOGE << "Failed to notify ForkContextListener that fork is finished (std::weak_ptr of listener is empty)";
	}
}

std::shared_ptr<BranchInfo> ForkMessageContextDbProxy::onDispatchNeeded(const shared_ptr<ForkContext>&,
                                                                        const shared_ptr<ExtendedContact>& newContact) {
	if (const auto forkContextListener = mForkContextListener.lock()) {
		mCurrentVersion++;
		return forkContextListener->onDispatchNeeded(shared_from_this(), newContact);
	}
	LOGE << "Failed to notify ForkContextListener that a dispatch is needed (std::weak_ptr of listener is empty)";
	return nullptr;
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

	if (const auto forkContextListener = mForkContextListener.lock()) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid, reason);
	} else {
		LOGE << "Failed to notify ForkContextListener of useless registration (std::weak_ptr of listener is empty)";
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

			    if (!thiz->mAgent) return;

			    thiz->mAgent->getRoot()->addToMainLoop(
			        [weakFork = weak_ptr<ForkMessageContextDbProxy>{thiz->shared_from_this()}]() {
				        if (const auto fork = weakFork.lock()) fork->clearMemoryIfPossible();
			        });
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
	const auto forkContextListener = mForkContextListener.lock();
	if (!forkContextListener) {
		LOGE << "Failed to notify ForkContextListener (std::weak_ptr of listener is empty)";
		return;
	}

	// Do not access DB or call OnNewRegister if we already know that this device is delivered.
	if (isAlreadyDelivered(dest, uid)) {
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
		                                                   DispatchStatus::DispatchNotNeeded);
		return;
	}

	// Try to restore the ForkMessage from a previous recursive call.
	if (!restoreForkIfNeeded()) { // runtime_error during restoration
		forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
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

			if (thiz->mAgent) {
				LOGD_CTX(thiz->mLogPrefix, "onNewRegister")
				    << "Loaded or previously loaded, recursively added to main loop (thread)";
				thiz->mAgent->getRoot()->addToMainLoop(
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
			// TODO: yes, this is ugly but I do not have a better solution for now.
			if (const auto router = dynamic_pointer_cast<ModuleRouter>(mAgent->findModuleByRole("Router"))) {
				const auto factory = router->getForkManager()->getFactory();
				mForkMessage = factory->restoreForkMessageContext(*mDbFork, shared_from_this());
			} else {
				return false;
			}
			mDbFork.reset();

			// Timer is now handle by the newly restored inner ForkMessageContext
			mProxyLateTimer.stop();
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

ostream& operator<<(ostream& os, ForkMessageContextDbProxy::State state) noexcept {
	switch (state) {
		case ForkMessageContextDbProxy::State::IN_DATABASE:
			return os << "IN_DATABASE";
		case ForkMessageContextDbProxy::State::IN_MEMORY:
			return os << "IN_MEMORY";
	}
	return os << "Unknown";
}

std::shared_ptr<BranchInfo> ForkMessageContextDbProxy::addBranch(std::unique_ptr<RequestSipEvent>&& ev,
                                                                 const std::shared_ptr<ExtendedContact>& contact) {
	checkState(__FUNCTION__, State::IN_MEMORY);
	auto newBranch = mForkMessage->addBranch(std::move(ev), contact);
	newBranch->setForkContext(shared_from_this());

	return newBranch;
}

bool ForkMessageContextDbProxy::allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const {
	if (getState() != State::IN_MEMORY) return true;
	return mForkMessage->allCurrentBranchesAnswered(finalStatusMode);
}

bool ForkMessageContextDbProxy::hasNextBranches() const {
	if (getState() != State::IN_MEMORY) return false;
	return mForkMessage->hasNextBranches();
}

void ForkMessageContextDbProxy::processInternalError(int status, const char* phrase) {
	checkState(__FUNCTION__, State::IN_MEMORY);
	mForkMessage->processInternalError(status, phrase);
}

void ForkMessageContextDbProxy::start() {
	checkState(__FUNCTION__, State::IN_MEMORY);
	mForkMessage->start();
}

void ForkMessageContextDbProxy::addKey(const string& key) {
	checkState(__FUNCTION__, State::IN_MEMORY);
	mForkMessage->addKey(key);
}

const vector<string>& ForkMessageContextDbProxy::getKeys() const {
	if (getState() == State::IN_MEMORY) {
		return mForkMessage->getKeys();
	} else {
		return mSavedKeys;
	}
}

bool ForkMessageContextDbProxy::isFinished() const {
	return mIsFinished;
}

std::shared_ptr<BranchInfo> ForkMessageContextDbProxy::tryToSendFinalResponse() {
	checkState(__FUNCTION__, State::IN_MEMORY);
	return mForkMessage->tryToSendFinalResponse();
}

RequestSipEvent& ForkMessageContextDbProxy::getEvent() {
	checkState(__FUNCTION__, State::IN_MEMORY);
	return mForkMessage->getEvent();
}

const std::shared_ptr<ForkContextConfig>& ForkMessageContextDbProxy::getConfig() const {
	return mSavedConfig;
}

sofiasip::MsgSipPriority ForkMessageContextDbProxy::getMsgPriority() const {
	return mSavedMsgPriority;
}

const std::shared_ptr<IncomingTransaction>& ForkMessageContextDbProxy::getIncomingTransaction() const {
	checkState(__FUNCTION__, State::IN_MEMORY);
	return mForkMessage->getIncomingTransaction();
}

std::unique_ptr<ResponseSipEvent> ForkMessageContextDbProxy::onSendResponse(std::unique_ptr<ResponseSipEvent>&& event) {
	if (mForkMessage) return mForkMessage->onSendResponse(std::move(event));
	return std::move(event);
}

const char* ForkMessageContextDbProxy::getClassName() const {
	return kClassName.data();
}

const ForkContext* ForkMessageContextDbProxy::getPtrForEquality() const {
	if (mForkMessage) {
		return mForkMessage.get();
	}
	return this;
}

} // namespace flexisip