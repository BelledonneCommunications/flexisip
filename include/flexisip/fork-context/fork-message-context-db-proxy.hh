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

#pragma once

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
	static std::shared_ptr<ForkMessageContextDbProxy> make(Agent* agent,
	                                                       const std::shared_ptr<RequestSipEvent>& event,
	                                                       const std::shared_ptr<ForkContextConfig>& cfg,
	                                                       const std::weak_ptr<ForkContextListener>& listener,
	                                                       const std::weak_ptr<StatPair>& messageCounter,
	                                                       const std::weak_ptr<StatPair>& proxyCounter);

	static std::shared_ptr<ForkMessageContextDbProxy> make(Agent* agent,
	                                                       const std::shared_ptr<RequestSipEvent>& event,
	                                                       const std::shared_ptr<ForkContextConfig>& cfg,
	                                                       const std::weak_ptr<ForkContextListener>& listener,
	                                                       const std::weak_ptr<StatPair>& messageCounter,
	                                                       const std::weak_ptr<StatPair>& proxyCounter,
	                                                       ForkMessageContextDb& forkFromDb);

	~ForkMessageContextDbProxy();

	/**
	 * Called by the Router module to create a new branch.
	 */
	std::shared_ptr<BranchInfo> addBranch(const std::shared_ptr<RequestSipEvent>& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) override {
		if (!mForkMessage) loadFromDb();
		auto newBranch = mForkMessage->addBranch(ev, contact);
		newBranch->mForkCtx = shared_from_this();

		return newBranch;
	}

	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const override {
		if (!mForkMessage) return true;
		return mForkMessage->allCurrentBranchesAnswered(ignore_errors_and_timeouts);
	}

	/**
	 * Request if the fork has other branches with lower priorities to try
	 */
	bool hasNextBranches() const override {
		if (!mForkMessage) return false;
		return mForkMessage->hasNextBranches();
	}

	/**
	 * Called when a fatal internal error is thrown in Flexisip. Send a custom response and cancel all branches if
	 * necessary.
	 * @param status The status of the custom response to send.
	 * @param phrase The content of the custom response to send.
	 */
	void processInternalError(int status, const char* phrase) override {
		if (!mForkMessage) loadFromDb();
		mForkMessage->processInternalError(status, phrase);
	}

	/**
	 * Start the processing of the highest priority branches that are not completed yet
	 */
	void start() override {
		if (!mForkMessage) loadFromDb();
		mForkMessage->start();
	}

	void addKey(const std::string& key) override {
		if (!mForkMessage) loadFromDb();
		mForkMessage->addKey(key);
	}

	const std::vector<std::string>& getKeys() const override {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->getKeys();
	}

	/**
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination, then it should return true, false otherwise.
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	 */
	bool onNewRegister(const url_t* dest, const std::string& uid) override {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->onNewRegister(dest, uid);
	}

	void onPushSent(const std::shared_ptr<OutgoingTransaction>& tr) override {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onPushSent(tr);
	}

	void onPushError(const std::shared_ptr<OutgoingTransaction>& tr, const std::string& errormsg) override {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onPushError(tr, errormsg);
	}

	/**
	 * Notifies the cancellation of the fork process.
	 */
	void onCancel(const std::shared_ptr<RequestSipEvent>& ev) override {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onCancel(ev);
	}

	/**
	 * Notifies the arrival of a new response on a given branch
	 */
	void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) override {
		LOGD("ForkMessageContextDbProxy[%p] onResponse", this);
		if (!mForkMessage) loadFromDb();
		mForkMessage->onResponse(br, event);
		if (!mForkUuidInDb.empty()) {
			saveToDb(); // Only necessary if we keep deleted messages
		} else if (mForkMessage->allBranchesAnswered() && !mForkMessage->isFinished()) {
			saveToDb();
		}
	}

	const std::shared_ptr<RequestSipEvent>& getEvent() override {
		return savedRequest;
	}

	const std::shared_ptr<ForkContextConfig>& getConfig() const override {
		return savedConfig;
	}

	bool isFinished() const override {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->isFinished();
	}

#ifdef ENABLE_UNIT_TESTS
	void assertEqual(const std::shared_ptr<ForkMessageContextDbProxy>& expected) {
		BC_ASSERT_STRING_EQUAL(mForkUuidInDb.c_str(), expected->mForkUuidInDb.c_str());
		mForkMessage->assertEqual(expected->mForkMessage);
	}
#endif

private:
	ForkMessageContextDbProxy(Agent* agent,
	                          const std::shared_ptr<RequestSipEvent>& event,
	                          const std::shared_ptr<ForkContextConfig>& cfg,
	                          const std::weak_ptr<ForkContextListener>& listener,
	                          const std::weak_ptr<StatPair>& messageCounter,
	                          const std::weak_ptr<StatPair>& proxyCounter);

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) override;

	void loadFromDb() const;
	void saveToDb();

	mutable std::shared_ptr<ForkMessageContext> mForkMessage;
	std::weak_ptr<ForkContextListener> mOriginListener;
	std::string mForkUuidInDb{};
	std::weak_ptr<StatPair> mCounter;

	Agent* savedAgent;
	std::shared_ptr<RequestSipEvent> savedRequest;
	std::shared_ptr<ForkContextConfig> savedConfig;
	std::weak_ptr<StatPair> savedCounter;
};

} // namespace flexisip
