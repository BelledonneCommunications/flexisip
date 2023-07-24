/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include <list>

#include "flexisip/event.hh"
#include "flexisip/module-router.hh"
#include "flexisip/sofia-wrapper/timer.hh"

#include "eventlogs/events/eventlogs.hh"
#include "fork-status.hh"

#include "fork-context-base.hh"

namespace flexisip {

class ForkCallContext : public ForkContextBase {
public:
	// Call the matching private ctor and instantiate as a shared_ptr.
	template <typename... Args>
	static std::shared_ptr<ForkCallContext> make(Args&&... args) {
		return std::shared_ptr<ForkCallContext>{new ForkCallContext{std::forward<Args>(args)...}};
	}

	~ForkCallContext();

	// Public methods
	bool isCompleted() const;
	bool isRingingSomewhere() const;

	void onCancel(const std::shared_ptr<RequestSipEvent>& ev) override;

	void processInternalError(int status, const char* phrase) override;

protected:
	// Protected methods
	void onResponse(const std::shared_ptr<BranchInfo>& br, const std::shared_ptr<ResponseSipEvent>& event) override;

	/**
	 * See PushNotificationContextObserver::onPushSent()
	 */
	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept override;

	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;

	void start() override;

	const char* getClassName() const override {
		return CLASS_NAME;
	};

private:
	// Private ctors
	ForkCallContext(const std::shared_ptr<ModuleRouter>& router,
	                const std::shared_ptr<RequestSipEvent>& event,
	                sofiasip::MsgSipPriority priority);

	// Private methods
	const int* getUrgentCodes();
	void onShortTimer();
	void onLateTimeout() override;
	void cancelOthers(const std::shared_ptr<BranchInfo>& br, sip_t* received_cancel);
	void cancelOthersWithStatus(const std::shared_ptr<BranchInfo>& br, ForkStatus status);
	void logResponse(const std::shared_ptr<ResponseSipEvent>& ev, const BranchInfo*);
	void forwardThenLogResponse(const std::shared_ptr<BranchInfo>&);
	void cancelBranch(const std::shared_ptr<BranchInfo>& brit);
	bool shouldFinish() override {
		return !mCfg->mForkLate;
	}

	// Private attributes
	sofiasip::Home mHome{};
	std::unique_ptr<sofiasip::Timer> mShortTimer{}; // optionally used to send retryable responses
	std::shared_ptr<CallLog> mLog{};
	bool mCancelled = false;
	sip_reason_t* mCancelReason = nullptr;
	static const int sUrgentCodesWithout603[];
	static constexpr auto CLASS_NAME = "ForkCallContext";
};

} // namespace flexisip
