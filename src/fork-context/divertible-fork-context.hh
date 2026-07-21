/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <forward_list>
#include <memory>
#include <string>
#include <unordered_set>

#include "agent-interface.hh"
#include "agent.hh"
#include "branch-info.hh"
#include "call-step.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/utils/sip-uri.hh"
#include "flexisip/utils/stl-backports.hh"
#include "fork-context.hh"
#include "fork.hh"
#include "router/injector.hh"
#include "transaction/incoming-transaction.hh"

namespace flexisip {
class ForkManager;
class DivertibleForkEntry;

struct ForkCallContextConfig : ForkContextConfig {
	bool mCallDiversionEnabled{};
	SipUri mVoicemailServerUri{};
	std::unordered_set<int> mStatusCodes{};
};

/**
 * @brief It can manage a set of Fork units that are linked to the same request.
 */
class DivertibleForkContext : public std::enable_shared_from_this<DivertibleForkContext> {
public:
	template <typename... Args>
	static std::shared_ptr<ForkContext> make(Args&&... args) {
		auto context = std::shared_ptr<DivertibleForkContext>(new DivertibleForkContext{std::forward<Args>(args)...});
		context->registerFork();

		const auto config = static_pointer_cast<ForkCallContextConfig>(context->mCfg);
		if (!config->mCallDiversionEnabled ||
		    !context->mAgent->getSpacesStore()->getAccountsStore(SpacesStore::kLegacyDomainName).has_value()) {
			auto fork = context->addForkUnit(config->mStatusCodes, CallStep::Initial);
			if (config->mVoicemailServerUri.empty()) return fork;

			context->addForkToManager(fork, context->mInitialTarget, [ctx = std::weak_ptr(context)](bool) {
				const auto context = ctx.lock();
				if (!context) return;
				context->divert(404);
			});
			return {};
		}

		// Check if target has an 'Always' diversion.
		const auto accountStore = context->mAgent->getSpacesStore()->getAccountsStore(SpacesStore::kLegacyDomainName);
		accountStore->get().checkCallDiversions(
		    context->mInitialTarget, flexiapi::CallForwarding::Type::Always,
		    [ctx = std::weak_ptr(context)](const SipUri& target) mutable {
			    auto context = ctx.lock();
			    if (!context) return;
			    if (target.empty()) {
				    context->getEvent().reply(SIP_482_LOOP_DETECTED, TAG_END());
				    // destroy context
				    context->mUnregisterCB();
				    return;
			    }

			    const auto config = static_pointer_cast<ForkCallContextConfig>(context->mCfg);
			    auto fork = context->addForkUnit(config->mStatusCodes, CallStep::Initial);
			    context->addForkToManager(fork, target, [ctx](bool) {
				    const auto context = ctx.lock();
				    if (!context) return;
				    const auto config = static_pointer_cast<ForkCallContextConfig>(context->mCfg);
				    if (!config->mVoicemailServerUri.empty() && context->divert(404)) {
					    return;
				    }
				    context->getEvent().reply(SIP_404_NOT_FOUND, TAG_END());
				    context->mUnregisterCB();
			    });
		    });
		return {};
	}

	~DivertibleForkContext();

	std::shared_ptr<BranchInfo> addBranch(const std::shared_ptr<Fork>& fork,
	                                      std::unique_ptr<RequestSipEvent>&& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact);
	void start(const std::shared_ptr<Fork>& fork);
	void onResponse(const std::shared_ptr<Fork>& fork, const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev);
	void onNewRegister(const std::shared_ptr<Fork>& fork,
	                   const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact);

	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept;
	void onCancel(const sofiasip::MsgSip& ms);
	void processInternalError(int status, const char* phrase);
	bool isFinished() const;

	void removeFork(const std::shared_ptr<Fork>& fork);

	RequestSipEvent& getEvent() {
		return *mEvent;
	}
	sofiasip::MsgSipPriority getMsgPriority() const {
		return mMsgPriority;
	}
	const std::shared_ptr<ForkContextConfig>& getConfig() const {
		return mCfg;
	}
	std::shared_ptr<InjectorListener> getInjectorListener() const {
		return mInjectorListener.lock();
	}
	std::shared_ptr<ForkContextListener> getForkContextListener() const;

	void onForkContextFinished(const std::shared_ptr<Fork>& fork);

	std::unique_ptr<ResponseSipEvent> sendResponse(std::unique_ptr<ResponseSipEvent>&& event);
	const std::shared_ptr<IncomingTransaction>& getIncomingTransaction() {
		return mIncoming;
	}

private:
	DivertibleForkContext(AgentInterface* agent,
	                      const std::shared_ptr<ForkContextConfig>& cfg,
	                      const std::weak_ptr<InjectorListener>& injectorListener,
	                      const std::weak_ptr<ForkManager>& forkManager,
	                      std::unique_ptr<RequestSipEvent>&& event,
	                      sofiasip::MsgSipPriority priority,
	                      const std::weak_ptr<StatPair>& counter);

	// Add an entry into the ForkManager to keep this class alive even if no Fork are managed (awaiting a CB).
	void registerFork();

	/**
	 * Add a fork to the managed fork list.
	 * @param filteredCodes the fork response codes that must be intercepted instead of sending them to the incoming
	 * transaction.
	 * @param callStep the step of call among Initial and Diverted.
	 * @return generated DivertibleForkEntry.
	 */
	std::shared_ptr<ForkContext> addForkUnit(const std::unordered_set<int>& filterCodes, CallStep callStep);

	/**
	 * Delegate fork preparation to ForkManager.
	 * @param fork the fork that will be in charge of context for this AOR.
	 * @param sipUri the AOR of the target.
	 * @param onEmptyContacts the callback when no valid contacts are found.
	 */
	void addForkToManager(const std::shared_ptr<ForkContext>& fork,
	                      const SipUri& sipUri,
	                      stl_backports::move_only_function<void(bool)>&& onEmptyContacts);
	/**
	 * If a response to the incoming transaction has been filtered, try to divert the call.
	 * @param fork the fork to consider
	 */
	void divertIfResponseHasBeenFiltered(Fork& fork);
	/**
	 * Try to create a new fork to divert the call.
	 * @param code the 'cause' code to insert into the request URI.
	 * @return true on success.
	 */
	bool divert(int code);

	AgentInterface* mAgent;
	sofiasip::MsgSipPriority mMsgPriority = sofiasip::MsgSipPriority::Normal;
	std::shared_ptr<ForkContextConfig> mCfg;
	std::weak_ptr<InjectorListener> mInjectorListener;
	std::weak_ptr<ForkManager> mForkManager;
	std::weak_ptr<StatPair> mStatCounter;
	std::string mLogPrefix;
	std::function<void()> mUnregisterCB;
	int mDivertedCount{};
	std::forward_list<std::shared_ptr<Fork>> mForks;
	std::unique_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<IncomingTransaction> mIncoming;
	SipUri mInitialTarget{};
};
} // namespace flexisip