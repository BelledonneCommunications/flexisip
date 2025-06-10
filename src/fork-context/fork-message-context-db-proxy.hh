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

#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "fork-context/fork-context-base.hh"
#include "fork-message-context.hh"

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
	 * @brief State of a ForkMessageContextDbProxy object.
	 * - IN_DATABASE : means the instance is not present in memory and should be restored from DB before accessing it.
	 * - IN_MEMORY : means the instance is present in memory, no restoration needed.
	 */
	enum class State : uint8_t { IN_DATABASE, IN_MEMORY };

	template <typename... Args>
	static std::shared_ptr<ForkMessageContextDbProxy> make(Args&&... args) {
		return std::shared_ptr<ForkMessageContextDbProxy>{new ForkMessageContextDbProxy{std::forward<Args>(args)...}};
	}

	static std::shared_ptr<ForkMessageContextDbProxy>
	restore(ForkMessageContextDb& forkContextFromDb,
	        const std::weak_ptr<ForkContextListener>& forkContextListener,
	        const std::weak_ptr<InjectorListener>& injectorListener,
	        Agent* agent,
	        const std::shared_ptr<ForkContextConfig>& config,
	        const std::weak_ptr<StatPair>& forkMessageCounter,
	        const std::weak_ptr<StatPair>& counter);

	~ForkMessageContextDbProxy() override;

	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept override;

	std::shared_ptr<BranchInfo> addBranch(std::unique_ptr<RequestSipEvent>&& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) override;
	bool allCurrentBranchesAnswered(FinalStatusMode finalStatusMode) const override;
	bool hasNextBranches() const override;
	void processInternalError(int status, const char* phrase) override;
	void start() override;
	void addKey(const std::string& key) override;
	const std::vector<std::string>& getKeys() const override;
	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;
	void onCancel(const sofiasip::MsgSip&) override {};
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& event) override;
	bool isFinished() const override;
	std::shared_ptr<BranchInfo> checkFinished() override;
	RequestSipEvent& getEvent() override;
	const std::shared_ptr<ForkContextConfig>& getConfig() const override;
	sofiasip::MsgSipPriority getMsgPriority() const override;
	std::unique_ptr<ResponseSipEvent> onForwardResponse(std::unique_ptr<ResponseSipEvent>&& event) override;

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) override;
	std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>& ctx,
	                                             const std::shared_ptr<ExtendedContact>& newContact) override;
	void onUselessRegisterNotification(const std::shared_ptr<ForkContext>& ctx,
	                                   const std::shared_ptr<ExtendedContact>& newContact,
	                                   const SipUri& dest,
	                                   const std::string& uid,
	                                   const DispatchStatus reason) override;

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContextDbProxy>& expected) {
		BC_ASSERT_STRING_EQUAL(mForkUuidInDb.c_str(), expected->mForkUuidInDb.c_str());
		mForkMessage->assertEqual(expected->mForkMessage);
	}
#endif

protected:
	static constexpr std::string_view kClassName{"ForkMessageContextDbProxy"};

	const ForkContext* getPtrForEquality() const override;
	const char* getClassName() const override;

private:
	/**
	 * @brief Create a new instance from a request.
	 */
	ForkMessageContextDbProxy(std::unique_ptr<RequestSipEvent>&& event,
	                          sofiasip::MsgSipPriority priority,
	                          bool isRestored,
	                          const std::weak_ptr<ForkContextListener>& forkContextListener,
	                          const std::weak_ptr<InjectorListener>& injectorListener,
	                          Agent* agent,
	                          const std::shared_ptr<ForkContextConfig>& config,
	                          const std::weak_ptr<StatPair>& forkMessageCounter,
	                          const std::weak_ptr<StatPair>& counter);

	/**
	 * @brief Load the ForkMessageContext instance from the database.
	 *
	 * @warning blocking I/O operation with the database, MUST be called in a thread.
	 */
	void loadFromDb() const;
	/**
	 * @brief Save the ForkMessageContext instance (and all corresponding branches) into the database.
	 *
	 * @warning blocking I/O operation with the database, MUST be called in a thread.
	 */
	bool saveToDb(const ForkMessageContextDb& dbFork);
	/**
	 * @brief Compare the provided state to the current state.
	 */
	void checkState(const std::string& methodName, const ForkMessageContextDbProxy::State& expectedState) const;
	/**
	 * @return 'true' if this instance can be saved into the database.
	 */
	bool canBeSaved() const;
	/**
	 * @brief Clear the ForkMessageContext instance from memory if possible.
	 */
	void clearMemoryIfPossible();
	void startTimerAndResetFork(time_t expirationDate, const std::vector<std::string>& keys);
	void startTimerAndResetFork();
	/**
	 * @param uri destination SIP URI
	 * @param uid destination unique id
	 * @return 'true' if the destination has already been delivered
	 */
	bool isAlreadyDelivered(const SipUri& uri, const std::string& uid);
	/**
	 * @brief Restore ForkMessageContext instance from mDbFork.
	 * @return 'true' if the operation succeeded or was not necessary.
	 */
	bool restoreForkIfNeeded();
	/**
	 * @brief Executes saveToDb in a separate thread.
	 */
	void runSavingThread();

	State getState() const;
	void setState(State mState);

	Agent* mAgent;
	// Attributes are indicated as mutable because they are used in const methods from ForkContext API, but they need to
	// be modified because we are in the proxy object.
	mutable std::shared_ptr<ForkMessageContext> mForkMessage;
	mutable std::unique_ptr<ForkMessageContextDb> mDbFork;
	mutable std::recursive_mutex mStateMutex;
	mutable std::mutex mDbAccessMutex;
	// Never access mState without mStateMutex locked, you can use locked getter and setter.
	mutable State mState;
	mutable std::atomic_uint mCurrentVersion{1};
	mutable std::atomic_uint mLastSavedVersion{0};
	mutable sofiasip::Timer mProxyLateTimer;
	// tuple<host, port, uid>
	mutable std::set<std::tuple<std::string, std::string, std::string>> mAlreadyDelivered;
	std::weak_ptr<StatPair> mCounter;
	std::string mForkUuidInDb;
	bool mIsFinished{};
	std::weak_ptr<ForkContextListener> mForkContextListener;
	std::shared_ptr<ForkContextConfig> mSavedConfig;
	std::vector<std::string> mSavedKeys;
	sofiasip::MsgSipPriority mSavedMsgPriority;
	const unsigned int mMaxThreadNumber;
	std::string mLogPrefix;
};

std::ostream& operator<<(std::ostream& os, ForkMessageContextDbProxy::State state) noexcept;

} // namespace flexisip