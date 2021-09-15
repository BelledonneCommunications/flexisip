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

#include "flexisip/fork-context/fork-message-context.hh"

namespace flexisip {

class ForkMessageContextDbProxy : public ForkContext,
                                  public ForkContextListener,
                                  public std::enable_shared_from_this<ForkMessageContextDbProxy> {
public:
	static std::shared_ptr<ForkMessageContextDbProxy> make(Agent* agent, const std::shared_ptr<RequestSipEvent>& event,
	                                                       std::shared_ptr<ForkContextConfig> cfg,
	                                                       std::weak_ptr<ForkContextListener> listener,
	                                                       std::weak_ptr<StatPair> counter) {
		const std::shared_ptr<ForkMessageContextDbProxy> shared{new ForkMessageContextDbProxy(listener)};
		shared->mForkMessage =
		    std::make_shared<ForkMessageContext>(agent, event, cfg, shared->shared_from_this(), counter);

		return shared;
	}

	/**
	 * Called by the Router module to create a new branch.
	 */
	void addBranch(const std::shared_ptr<RequestSipEvent>& ev, const std::shared_ptr<ExtendedContact>& contact) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->addBranch(ev, contact);
	}

	bool allCurrentBranchesAnswered(bool ignore_errors_and_timeouts = false) const {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->allCurrentBranchesAnswered(ignore_errors_and_timeouts);
	}

	/**
	 * Request if the fork has other branches with lower priorities to try
	 */
	bool hasNextBranches() const {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->hasNextBranches();
	}

	/**
	 * Called when a fatal internal error is thrown in Flexisip. Send a custom response and cancel all branches if
	 * necessary.
	 * @param status The status of the custom response to send.
	 * @param phrase The content of the custom response to send.
	 */
	void processInternalError(int status, const char* phrase) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->processInternalError(status, phrase);
	}

	/**
	 * Start the processing of the highest priority branches that are not completed yet
	 */
	void start() {
		if (!mForkMessage) loadFromDb();
		mForkMessage->start();
	}

	void addKey(const std::string& key) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->addKey(key);
	}

	const std::list<std::string>& getKeys() const {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->getKeys();
	}

	/**
	 * Informs the forked call context that a new register from a potential destination of the fork just arrived.
	 * If the fork context is interested in handling this new destination, then it should return true, false otherwise.
	 * Typical case for refusing it is when another transaction already exists or existed for this contact.
	 */
	bool onNewRegister(const url_t* dest, const std::string& uid) {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->onNewRegister(dest, uid);
	}

	void onPushSent(const std::shared_ptr<OutgoingTransaction>& tr) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onPushSent(tr);
	}

	void onPushError(const std::shared_ptr<OutgoingTransaction>& tr, const std::string& errormsg) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onPushError(tr, errormsg);
	}

	/**
	 * Notifies the cancellation of the fork process.
	 */
	void onCancel(const std::shared_ptr<RequestSipEvent>& ev) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onCancel(ev);
	}

	/**
	 * Notifies the arrival of a new response on a given branch
	 */
	void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) {
		if (!mForkMessage) loadFromDb();
		mForkMessage->onResponse(br, event);
	}

	const std::shared_ptr<RequestSipEvent>& getEvent() {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->getEvent();
	}

	const std::shared_ptr<ForkContextConfig>& getConfig() const {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->getConfig();
	}

	bool isFinished() const {
		if (!mForkMessage) loadFromDb();
		return mForkMessage->isFinished();
	}

	void onForkContextFinished(std::shared_ptr<ForkContext> ctx) {
		if (auto originListener = mOriginListener.lock()) {
			originListener->onForkContextFinished(shared_from_this());
		}
	}

private:
	ForkMessageContextDbProxy(std::weak_ptr<ForkContextListener> listener) : mForkMessage{}, mOriginListener{listener} {
	}

	void loadFromDb() const {
		SLOGD << "Fork loaded from DB";
	}

	void saveToDb() {
		SLOGD << "Fork saved to DB";
	}

	mutable std::shared_ptr<ForkMessageContext> mForkMessage;
	std::weak_ptr<ForkContextListener> mOriginListener;
};

} // namespace flexisip
