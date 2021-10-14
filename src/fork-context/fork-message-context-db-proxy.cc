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

using namespace flexisip;
using namespace std;

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
	shared->mForkMessage = ForkMessageContext::make(agent, event, cfg, shared, messageCounter);

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
	if(!event) {
		SLOGD << "Event is empty this will crash TODO"; // TODO
	}
	// new because make_shared require a public constructor.
	const shared_ptr<ForkMessageContextDbProxy> shared{
	    new ForkMessageContextDbProxy(agent, event, cfg, listener, messageCounter, proxyCounter)};
	shared->mForkMessage = ForkMessageContext::make(agent, event, cfg, shared, messageCounter, forkFromDb);

	return shared;
}

ForkMessageContextDbProxy::ForkMessageContextDbProxy(Agent* agent,
                                                     const std::shared_ptr<RequestSipEvent>& event,
                                                     const std::shared_ptr<ForkContextConfig>& cfg,
                                                     const std::weak_ptr<ForkContextListener>& listener,
                                                     const std::weak_ptr<StatPair>& messageCounter,
                                                     const std::weak_ptr<StatPair>& proxyCounter)
    : mForkMessage{}, mOriginListener{listener}, mCounter{proxyCounter},
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
	if (!mForkUuidInDb.empty()) {
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
}

void ForkMessageContextDbProxy::saveToDb() {
	LOGI("ForkMessageContextDbProxy[%p] saving ForkMessage to DB.", this);
	if (mForkUuidInDb.empty()) {
		LOGD("ForkMessageContextDbProxy[%p] not saved before, creating a new entry.", this);
		mForkUuidInDb = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(mForkMessage);
	} else {
		LOGD("ForkMessageContextDbProxy[%p] already in DB with UUID[%s], updating", this, mForkUuidInDb.c_str());
		ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(mForkMessage, mForkUuidInDb);
	}
	mForkMessage.reset();
}

void ForkMessageContextDbProxy::onForkContextFinished(const shared_ptr<ForkContext>& ctx) {
	if (auto originListener = mOriginListener.lock()) {
		originListener->onForkContextFinished(shared_from_this());
	}
}
