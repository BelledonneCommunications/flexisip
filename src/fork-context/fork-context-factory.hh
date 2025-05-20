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

#include <memory>

#include "flexisip/configmanager.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "fork-basic-context.hh"
#include "fork-call-context.hh"
#include "fork-message-context-db-proxy.hh"
#include "fork-message-context.hh"

namespace flexisip {

/**
 * @brief Provides easy-to-use methods for creating ForkContext instances.
 */
class ForkContextFactory {
public:
	ForkContextFactory() = delete;
	ForkContextFactory(Agent* agent,
	                   const std::weak_ptr<ForkStats>& forkStats,
	                   const std::weak_ptr<InjectorListener>& injectorListener,
	                   const std::weak_ptr<ForkContextListener>& forkContextListener,
	                   const GenericStruct* moduleRouterConfig);

	~ForkContextFactory() = default;

	template <typename... Args>
	std::shared_ptr<ForkContext> makeForkBasicContext(Args&&... args) const {
		std::weak_ptr<StatPair> statCounter{};
		if (const auto forkStats = mForkStats.lock()) statCounter = forkStats->mCountBasicForks;
		return ForkBasicContext::make(std::forward<Args>(args)..., mForkContextListener, mInjectorListener, mAgent,
		                              mOtherForkCfg, statCounter);
	}

	template <typename... Args>
	std::shared_ptr<ForkContext> makeForkCallContext(Args&&... args) const {
		std::weak_ptr<StatPair> statCounter{};
		if (const auto forkStats = mForkStats.lock()) statCounter = forkStats->mCountCallForks;
		return ForkCallContext::make(std::forward<Args>(args)..., mForkContextListener, mInjectorListener, mAgent,
		                             mCallForkCfg, statCounter);
	}

	/**
	 * @param isIntendedForConfServer MESSAGE requests intended for the conference server use a custom set of parameters
	 * @return a ForkMessageContext or a ForkMessageContextDbProxy if storage of MESSAGE requests in the database is
	 * enabled
	 */
	template <typename... Args>
	std::shared_ptr<ForkContext> makeForkMessageContext(bool isIntendedForConfServer, Args&&... args) const {
		std::weak_ptr<StatPair> statCounter{};
#if ENABLE_SOCI
		if (messageStorageInDbEnabled()) {
			std::weak_ptr<StatPair> forkMessageCounter{};
			if (const auto forkStats = mForkStats.lock()) {
				statCounter = forkStats->mCountMessageProxyForks;
				forkMessageCounter = forkStats->mCountMessageForks;
			}
			return ForkMessageContextDbProxy::make(std::forward<Args>(args)..., mForkContextListener, mInjectorListener,
			                                       mAgent, mMessageForkCfg, forkMessageCounter, statCounter);
		}
#endif
		if (isIntendedForConfServer) {
			if (const auto forkStats = mForkStats.lock()) statCounter = forkStats->mCountMessageConferenceForks;
			return ForkMessageContext::make(std::forward<Args>(args)..., mForkContextListener, mInjectorListener,
			                                mAgent, std::make_shared<ForkContextConfig>(), statCounter);
		}
		if (const auto forkStats = mForkStats.lock()) statCounter = forkStats->mCountMessageForks;
		return ForkMessageContext::make(std::forward<Args>(args)..., mForkContextListener, mInjectorListener, mAgent,
		                                mMessageForkCfg, statCounter);
	}

	template <typename... Args>
	std::shared_ptr<ForkMessageContext> restoreForkMessageContext(Args&&... args) const {
		std::weak_ptr<StatPair> statCounter{};
		if (const auto forkStats = mForkStats.lock()) statCounter = forkStats->mCountMessageForks;
		return ForkMessageContext::restore(std::forward<Args>(args)..., mInjectorListener, mAgent, mMessageForkCfg,
		                                   statCounter);
	}

#if ENABLE_SOCI
	template <typename... Args>
	std::shared_ptr<ForkMessageContextDbProxy> restoreForkMessageContextDbProxy(Args&&... args) const {
		std::weak_ptr<StatPair> statCounter{}, forkMessageCounter{};
		if (const auto forkStats = mForkStats.lock()) {
			statCounter = forkStats->mCountMessageProxyForks;
			forkMessageCounter = forkStats->mCountMessageForks;
		}
		return ForkMessageContextDbProxy::restore(std::forward<Args>(args)..., mInjectorListener, mAgent,
		                                          mMessageForkCfg, forkMessageCounter, statCounter);
	}
#endif

	bool callForkLateEnabled() const;
	bool messageForkLateEnabled() const;
	bool messageStorageInDbEnabled() const;

private:
	static constexpr std::string_view mLogPrefix{"ForkContextFactory"};

	Agent* mAgent{};
	std::weak_ptr<ForkStats> mForkStats{};
	std::weak_ptr<InjectorListener> mInjectorListener{};
	std::weak_ptr<ForkContextListener> mForkContextListener{};
	std::shared_ptr<ForkContextConfig> mCallForkCfg{};
	std::shared_ptr<ForkContextConfig> mOtherForkCfg{};
	std::shared_ptr<ForkContextConfig> mMessageForkCfg{};
};

} // namespace flexisip