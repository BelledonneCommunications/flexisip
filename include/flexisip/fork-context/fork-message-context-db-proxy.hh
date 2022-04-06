/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <string>

#include "flexisip/fork-context/fork-message-context-soci-repository.hh"
#include "flexisip/fork-context/fork-message-context.hh"

#if ENABLE_UNIT_TESTS
#include "bctoolbox/tester.h"
#endif

namespace flexisip {

class ForkMessageContextDbProxy : public ForkContext,
                                  public ForkContextListener,
                                  public std::enable_shared_from_this<ForkMessageContextDbProxy> {
public:
	enum class State : uint8_t { IN_DATABASE, SAVING, RESTORING, IN_MEMORY };

	/**
	 * Used to create a ForkMessageContextDbProxy and its inner ForkMessageContext when needed at runtime.
	 */
	static std::shared_ptr<ForkMessageContextDbProxy> make(Agent* agent,
	                                                       const std::shared_ptr<RequestSipEvent>& event,
	                                                       const std::shared_ptr<ForkContextConfig>& cfg,
	                                                       const std::weak_ptr<ForkContextListener>& listener,
	                                                       const std::weak_ptr<StatPair>& messageCounter,
	                                                       const std::weak_ptr<StatPair>& proxyCounter);

	/**
	 * Used to create a ForkMessageContextDbProxy object for a ForkMessage that already exist in database at server
	 * restart.
	 */
	static std::shared_ptr<ForkMessageContextDbProxy> make(Agent* agent,
	                                                       const std::shared_ptr<ForkContextConfig>& cfg,
	                                                       const std::weak_ptr<ForkContextListener>& listener,
	                                                       const std::weak_ptr<StatPair>& messageCounter,
	                                                       const std::weak_ptr<StatPair>& proxyCounter,
	                                                       ForkMessageContextDb& forkFromDb);

	~ForkMessageContextDbProxy() override;

	void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) override;
	bool onNewRegister(const SipUri& dest, const std::string& uid, const std::function<void()>& dispatchFunc) override;

	std::shared_ptr<BranchInfo> addBranch(const std::shared_ptr<RequestSipEvent>& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) override {
		checkState(__FUNCTION__, State::IN_MEMORY);
		auto newBranch = mForkMessage->addBranch(ev, contact);
		newBranch->mForkCtx = shared_from_this();

		return newBranch;
	}

	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const override {
		if (mState != State::IN_MEMORY) return true;
		return mForkMessage->allCurrentBranchesAnswered(ignore_errors_and_timeouts);
	}

	bool hasNextBranches() const override {
		if (mState != State::IN_MEMORY) return false;
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
		if (mState == State::IN_MEMORY) {
			return mForkMessage->getKeys();
		} else {
			return mSavedKeys;
		}
	}

	bool isFinished() const override {
		return mIsFinished;
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

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContextDbProxy>& expected) {
		BC_ASSERT_STRING_EQUAL(mForkUuidInDb.c_str(), expected->mForkUuidInDb.c_str());
		mForkMessage->assertEqual(expected->mForkMessage);
	}
#endif

private:
	ForkMessageContextDbProxy(Agent* agent,
	                          const std::shared_ptr<ForkContextConfig>& cfg,
	                          const std::weak_ptr<ForkContextListener>& listener,
	                          const std::weak_ptr<StatPair>& messageCounter,
	                          const std::weak_ptr<StatPair>& proxyCounter);

	ForkMessageContextDbProxy(Agent* agent,
	                          const std::shared_ptr<ForkContextConfig>& cfg,
	                          const std::weak_ptr<ForkContextListener>& listener,
	                          const std::weak_ptr<StatPair>& messageCounter,
	                          const std::weak_ptr<StatPair>& proxyCounter,
	                          ForkMessageContextDb& forkFromDb);

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) override;

	/**
	 * This method call the onNewRegister method and remove the ForkMessageContext from memory onNewRegister return
	 * false. Should be called on the main loop from a thread : @see ForkMessageContextDbProxy::onNewRegister.
	 * Must only be used when ForkMessageContextDbProxy has already been saved in DB once.
	 */
	void delayedOnNewRegister(const SipUri& dest, const std::string& uid, const std::function<void()>& dispatchFunc);

	/**
	 * Be careful, blocking I/O with DB, should be called in a thread.
	 */
	void loadFromDb() const;

	/**
	 * Be careful, blocking I/O with DB, should be called in a thread.
	 */
	bool saveToDb(const ForkMessageContextDb& dbFork);

	void checkState(const std::string& methodName, const ForkMessageContextDbProxy::State& expectedState) const;
	void startTimerAndResetFork(time_t expirationDate, const std::vector<std::string>& keys);
	void startTimerAndResetFork();

	/**
	 * Restore mForkMessage from mDbFork if mDbFork != nullptr
	 * @return true if the restoration succeed or wasn't needed. false in case of error.
	 */
	bool restoreForkIfNeeded();
	void runSavingThread();

	// All those attributes are mark as mutable because they are used in const methods from ForkContext API, but they
	// need to be modified because we are in the proxy object.
	mutable std::shared_ptr<ForkMessageContext> mForkMessage;
	mutable std::unique_ptr<ForkMessageContextDb> mDbFork{nullptr};
	mutable std::mutex mMutex{};
	mutable std::condition_variable mCondition{};
	mutable State mState;
	mutable sofiasip::Timer mProxyLateTimer;

	std::weak_ptr<ForkContextListener> mOriginListener;
	std::weak_ptr<StatPair> mCounter;
	std::string mForkUuidInDb{};
	bool mIsFinished = false;

	Agent* mSavedAgent;
	std::shared_ptr<ForkContextConfig> mSavedConfig;
	std::weak_ptr<StatPair> mSavedCounter;
	std::vector<std::string> mSavedKeys{};
};

std::ostream& operator<<(std::ostream& os, flexisip::ForkMessageContextDbProxy::State state) noexcept;

} // namespace flexisip
