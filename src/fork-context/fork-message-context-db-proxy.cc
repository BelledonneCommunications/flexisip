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

	// new because make_shared require a public constructor.
	const shared_ptr<ForkMessageContextDbProxy> shared{
	    new ForkMessageContextDbProxy(agent, event, cfg, shared, messageCounter, proxyCounter)};
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
	// new because make_shared require a public constructor.
	const shared_ptr<ForkMessageContextDbProxy> shared{
	    new ForkMessageContextDbProxy(agent, event, cfg, shared, messageCounter, proxyCounter)};
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

	if (auto sharedCounter = mCounter.lock()) {
		sharedCounter->incrStart();
	}
}

ForkMessageContextDbProxy::~ForkMessageContextDbProxy() {
	if (auto sharedCounter = mCounter.lock()) {
		sharedCounter->incrFinish();
	}
}

void ForkMessageContextDbProxy::loadFromDb() const {
	auto dbFork = ForkMessageContextSociRepository::getInstance()->findForkMessageByUuid(mForkUuidInDb);
	mForkMessage = ForkMessageContext::make(savedAgent, savedRequest, savedConfig, mOriginListener, savedCounter);
}

void ForkMessageContextDbProxy::saveToDb() {
	if (mForkUuidInDb.empty()) {
		mForkUuidInDb = ForkMessageContextSociRepository::getInstance()->saveForkMessageContext(mForkMessage);
	} else {
		ForkMessageContextSociRepository::getInstance()->updateForkMessageContext(mForkMessage, mForkUuidInDb);
	}
	mForkMessage.reset();
}

void ForkMessageContextDbProxy::onForkContextFinished(const shared_ptr<ForkContext>& ctx) {
	if (auto originListener = mOriginListener.lock()) {
		originListener->onForkContextFinished(shared_from_this());
	}
}
