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
#include "branch-info.hh"
#include "call-step.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "fork-context.hh"
#include "fork.hh"
#include "router/injector.hh"
#include "transaction/incoming-transaction.hh"

namespace flexisip {
struct ForkCallContextConfig : ForkContextConfig {
	SipUri mVoicemailServerUri{};
	std::unordered_set<int> mStatusCodes{};
};
class DivertibleForkContextListener : public ForkContextListener {
public:
	virtual ~DivertibleForkContextListener() override = default;
	virtual void addFork(const std::shared_ptr<ForkContext>& ctx,
	                     const url_t* url,
	                     const std::list<std::pair<sip_contact_t*, std::shared_ptr<ExtendedContact>>>& forkContacts,
	                     bool isInviteRequest) = 0;
};

/**
 * @brief It can manage a set of Fork units that are linked to the same request.
 */
class DivertibleForkContext : public std::enable_shared_from_this<DivertibleForkContext> {
public:
	template <typename... Args>
	static std::shared_ptr<ForkContext> make(bool hasContact, Args&&... args) {
		auto context = std::shared_ptr<DivertibleForkContext>(new DivertibleForkContext{std::forward<Args>(args)...});
		context->registerFork();
		if (!hasContact) {
			context->divert(404);
			return nullptr;
		}
		const auto config = static_pointer_cast<ForkCallContextConfig>(context->mCfg);
		return context->addForkUnit(
		    config->mVoicemailServerUri.empty() ? std::unordered_set<int>() : config->mStatusCodes, CallStep::Initial);
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
	std::shared_ptr<ForkContextListener> getForkContextListener() const {
		return mForkContextListener.lock();
	}

	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx);

	std::unique_ptr<ResponseSipEvent> sendResponse(std::unique_ptr<ResponseSipEvent>&& event);
	const std::shared_ptr<IncomingTransaction>& getIncomingTransaction() {
		return mIncoming;
	}

private:
	DivertibleForkContext(AgentInterface* agent,
	                      const std::shared_ptr<ForkContextConfig>& cfg,
	                      const std::weak_ptr<InjectorListener>& injectorListener,
	                      const std::weak_ptr<DivertibleForkContextListener>& forkContextListener,
	                      std::unique_ptr<RequestSipEvent>&& event,
	                      sofiasip::MsgSipPriority priority,
	                      const std::weak_ptr<StatPair>& counter);

	// Add an entry into the ForkManager to keep this class alive even if no Fork are managed (awaiting a CB).
	void registerFork();

	/**
	 *  Add a fork to a specific AOR
	 * @param filteredCodes the fork response codes that must be intercepted instead of sending them to the incoming
	 * transaction.
	 * @param callStep the step of call among Initial and Diverted.
	 * @return generated DivertibleForkEntry.
	 */
	std::shared_ptr<ForkContext> addForkUnit(const std::unordered_set<int>& filterCodes, CallStep callStep);
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
	std::weak_ptr<DivertibleForkContextListener> mForkContextListener;
	std::weak_ptr<StatPair> mStatCounter;
	std::string mLogPrefix;
	std::function<void()> mUnregisterCB;
	int mDivertedCount{};
	std::forward_list<std::shared_ptr<Fork>> mForks;
	std::unique_ptr<RequestSipEvent> mEvent;
	std::shared_ptr<IncomingTransaction> mIncoming;
};
} // namespace flexisip