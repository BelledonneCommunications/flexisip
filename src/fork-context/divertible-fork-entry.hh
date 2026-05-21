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

#include <memory>

#include "branch-info.hh"
#include "fork-context.hh"
#include "fork.hh"
#include "router/injector.hh"

namespace flexisip {

class DivertibleForkContext;

/**
 * @brief It implements the API of a ForkContext but gives access to a divertible fork context.
 */
class DivertibleForkEntry : public ForkContext,
                            public ForkContextListener,
                            public InjectorListener,
                            public std::enable_shared_from_this<DivertibleForkEntry> {
public:
	static std::shared_ptr<DivertibleForkEntry> make(const std::shared_ptr<DivertibleForkContext>& forkContext) {
		return std::shared_ptr<DivertibleForkEntry>(new DivertibleForkEntry(forkContext));
	}

	~DivertibleForkEntry() = default;

	void linkForkUnit(const std::shared_ptr<Fork>& unit);

	std::shared_ptr<BranchInfo> addBranch(std::unique_ptr<RequestSipEvent>&& ev,
	                                      const std::shared_ptr<ExtendedContact>& contact) final;
	void start() final;
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& ev) final;
	void
	onNewRegister(const SipUri& dest, const std::string& uid, const std::shared_ptr<ExtendedContact>& newContact) final;
	void processInternalError(int status, const char* phrase) final;
	void onCancel(const sofiasip::MsgSip& ms) final;
	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept final;
	bool isFinished() const final;
	RequestSipEvent& getEvent() final;
	sofiasip::MsgSipPriority getMsgPriority() const final;
	const std::shared_ptr<ForkContextConfig>& getConfig() const final;

	const ForkContext* getPtrForEquality() const final;

	void addKey(const std::string& key) final {
		mKeys.push_back(key);
	}
	const std::vector<std::string>& getKeys() const final {
		return mKeys;
	}

	// ForkContextListener
	std::shared_ptr<BranchInfo> onDispatchNeeded(const std::shared_ptr<ForkContext>&,
	                                             const std::shared_ptr<ExtendedContact>& newContact) final;
	void onUselessRegisterNotification(const std::shared_ptr<ForkContext>&,
	                                   const std::shared_ptr<ExtendedContact>& newContact,
	                                   const SipUri& dest,
	                                   const std::string& uid,
	                                   const DispatchStatus reason) final;
	void onForkContextFinished(const std::shared_ptr<ForkContext>& ctx) final;

	// InjectorListener
	void inject(std::unique_ptr<RequestSipEvent>&& event,
	            const std::shared_ptr<ForkContext>& forkContext,
	            const std::string& contactId) final;

private:
	explicit DivertibleForkEntry(const std::shared_ptr<DivertibleForkContext>& forkContext);

	std::shared_ptr<DivertibleForkContext> mForkContext;
	std::weak_ptr<Fork> mFork;
	std::string mLogPrefix;
	std::vector<std::string> mKeys;
};
} // namespace flexisip