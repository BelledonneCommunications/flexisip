/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <atomic>
#include <string>

#include "flexisip/fork-context/fork-message-context.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

namespace flexisip {

class ModuleRouter;

class ForkMessageContextDbProxy : public ForkContext,
                                  public ForkContextListener,
                                  public std::enable_shared_from_this<ForkMessageContextDbProxy> {
public:
	/**
	 * IN_DATABASE : means that ForkMessageContext is not present in memory and should be restored from DB before
	 * accessing it.
	 * IN_MEMORY : means that ForkMessageContext is present in memory, no restoration needed.
	 */
	enum class State : uint8_t { IN_DATABASE, IN_MEMORY };

	/**
	 * Used to create a ForkMessageContextDbProxy object for a ForkMessage that already exist in database at server
	 * restart.
	 */
	static std::shared_ptr<ForkMessageContextDbProxy> make(const std::shared_ptr<ModuleRouter>& router,
	                                                       ForkMessageContextDb& forkFromDb);

	/**
	 * Used to create a ForkMessageContextDbProxy and its inner ForkMessageContext when needed at runtime.
	 */
	static std::shared_ptr<ForkMessageContextDbProxy> make(const std::shared_ptr<ModuleRouter>& router,
	                                                       const std::shared_ptr<RequestSipEvent>& event,
	                                                       sofiasip::MsgSipPriority priority);

	~ForkMessageContextDbProxy() override;

	void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) override;
	/**
	 * See PushNotificationContextObserver::onPushSent().
	 */
	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept override;

	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;

	std::shared_ptr<BranchInfo> addBranch(const std::shared_ptr<RequestSipEvent>& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		auto newBranch = mForkMessage->addBranch(ev, contact);
		newBranch->mForkCtx = shared_from_this();

		return newBranch;
	}

	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const override {
		if (getState() != State::IN_MEMORY) return true;
		return mForkMessage->allCurrentBranchesAnswered(ignore_errors_and_timeouts);
	}

	bool hasNextBranches() const override {
		if (getState() != State::IN_MEMORY) return false;
		return mForkMessage->hasNextBranches();
	}

	void processInternalError(int status, const char* phrase) override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		mForkMessage->processInternalError(status, phrase);
	}

	void start() override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		mForkMessage->start();
	}

	void addKey(const std::string& key) override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		mForkMessage->addKey(key);
	}

	const std::vector<std::string>& getKeys() const override {
		if (getState() == State::IN_MEMORY) {
			return mForkMessage->getKeys();
		} else {
			return mSavedKeys;
		}
	}

	bool isFinished() const override {
		return mIsFinished;
	}

	void checkFinished() override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		mForkMessage->checkFinished();
	}

	const std::shared_ptr<RequestSipEvent>& getEvent() override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		return mForkMessage->getEvent();
	}

	const std::shared_ptr<ForkContextConfig>& getConfig() const override {
		return mSavedConfig;
	}

	void onCancel(const std::shared_ptr<RequestSipEvent>& ev) override {
		// Does nothing for fork late ForkMessageContext
	}

	sofiasip::MsgSipPriority getMsgPriority() const override {
		return mSavedMsgPriority;
	};

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContextDbProxy>& expected) {
		BC_ASSERT_STRING_EQUAL(mForkUuidInDb.c_str(), expected->mForkUuidInDb.c_str());
		mForkMessage->assertEqual(expected->mForkMessage);
	}
#endif

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) override;
	std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>& ctx,
	                                             const std::shared_ptr<ExtendedContact>& newContact) override;
	void onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
	                                   const std::shared_ptr<ExtendedContact>& newContact,
	                                   const SipUri& dest,
	                                   const std::string& uid,
	                                   const DispatchStatus reason) override;

protected:
	static constexpr auto CLASS_NAME = "ForkMessageContextDbProxy";
	const char* getClassName() const override {
		return CLASS_NAME;
	};

	const ForkContext* getPtrForEquality() const override {
		if (mForkMessage) {
			return mForkMessage.get();
		}
		return this;
	}

private:
	ForkMessageContextDbProxy(const std::shared_ptr<ModuleRouter> router, sofiasip::MsgSipPriority priority);
	ForkMessageContextDbProxy(const std::shared_ptr<ModuleRouter> router, ForkMessageContextDb& forkFromDb);

	/**
	 * Be careful, blocking I/O with DB, should be called in a thread.
	 */
	void loadFromDb() const;

	/**
	 * Be careful, blocking I/O with DB, should be called in a thread.
	 */
	bool saveToDb(const ForkMessageContextDb& dbFork);

	void checkState(const std::string& methodName, const ForkMessageContextDbProxy::State& expectedState) const;
	bool canBeSaved() const;
	void clearMemoryIfPossible();
	void startTimerAndResetFork(time_t expirationDate, const std::vector<std::string>& keys);
	void startTimerAndResetFork();
	bool isAlreadyDelivered(const SipUri& uri, const std::string& uid);

	/**
	 * Restore mForkMessage from mDbFork if mDbFork != nullptr
	 * @return true if the restoration succeed or wasn't needed. false in case of error.
	 */
	bool restoreForkIfNeeded();
	void runSavingThread();

	State getState() const;
	void setState(State mState);

	// All those attributes are mark as mutable because they are used in const methods from ForkContext API, but they
	// need to be modified because we are in the proxy object.
	mutable std::shared_ptr<ForkMessageContext> mForkMessage;
	mutable std::unique_ptr<ForkMessageContextDb> mDbFork{nullptr};
	mutable std::recursive_mutex mStateMutex{};
	mutable std::mutex mDbAccessMutex{};
	mutable State mState; // never access mState without mStateMutex locked, you can use locked getter and setter
	mutable std::atomic_uint mCurrentVersion{1};
	mutable std::atomic_uint mLastSavedVersion{0};
	mutable sofiasip::Timer mProxyLateTimer;
	// tuple<host, port, uid>
	mutable std::set<std::tuple<std::string, std::string, std::string>> mAlreadyDelivered;

	std::weak_ptr<StatPair> mCounter;
	std::string mForkUuidInDb{};
	bool mIsFinished = false;

	std::weak_ptr<ModuleRouter> mSavedRouter;
	std::shared_ptr<ForkContextConfig> mSavedConfig;
	std::vector<std::string> mSavedKeys{};
	sofiasip::MsgSipPriority mSavedMsgPriority;
};

std::ostream& operator<<(std::ostream& os, flexisip::ForkMessageContextDbProxy::State state) noexcept;

} // namespace flexisip
