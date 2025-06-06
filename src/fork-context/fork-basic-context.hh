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

#include "flexisip/event.hh"
#include "flexisip/module-router.hh"
#include "fork-context-base.hh"

namespace flexisip {

class ForkBasicContext : public ForkContextBase {
public:
	template <typename... Args>
	static std::shared_ptr<ForkBasicContext> make(Args&&... args) {
		return std::shared_ptr<ForkBasicContext>{new ForkBasicContext{std::forward<Args>(args)...}};
	}

	~ForkBasicContext() override;

	void processInternalError(int status, const char* phrase) override;

protected:
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& event) override;

	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override {
		if (const auto forkContextListener = mForkContextListener.lock())
			forkContextListener->onUselessRegisterNotification(shared_from_this(), newContact, dest, uid,
			                                                   DispatchStatus::DispatchNotNeeded);
	}

	static constexpr auto CLASS_NAME = "ForkBasicContext";
	const char* getClassName() const override {
		return CLASS_NAME;
	};

private:
	ForkBasicContext(std::unique_ptr<RequestSipEvent>&& event,
	                 sofiasip::MsgSipPriority priority,
	                 const std::weak_ptr<ForkContextListener>& forkContextListener,
	                 const std::weak_ptr<InjectorListener>& injectorListener,
	                 AgentInterface* agent,
	                 const std::shared_ptr<ForkContextConfig>& config,
	                 const std::weak_ptr<StatPair>& counter);

	void finishIncomingTransaction();
	void onDecisionTimer();

	// Timeout after which an answer must be sent through the incoming transaction even if no success response was
	// received on the outgoing transactions.
	std::unique_ptr<sofiasip::Timer> mDecisionTimer;
	std::string mLogPrefix;
};

} // namespace flexisip