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

#include <optional>

#include "eventlogs/events/eventlogs.hh"
#include "flexisip/event.hh"
#include "flexisip/module-router.hh"
#include "flexisip/sofia-wrapper/timer.hh"
#include "fork-context-base.hh"
#include "fork-status.hh"

namespace flexisip {

/**
 * @brief Handle the forking of SIP calls (INVITE requests). It manages the branches of the call and processes responses
 * from them.
 */
class ForkCallContext : public ForkContextBase {
public:
	template <typename... Args>
	static std::shared_ptr<ForkCallContext> make(Args&&... args) {
		return std::shared_ptr<ForkCallContext>{new ForkCallContext{std::forward<Args>(args)...}};
	}

	~ForkCallContext() override;

	void processInternalError(int status, const char* phrase) override;
	void onCancel(const MsgSip& ms) override;
	std::shared_ptr<BranchInfo> checkFinished() override;

	/**
	 * @return 'true' if the fork process is terminated
	 */
	bool isCompleted() const;
	/**
	 * @return 'true' if one of the branches received a response in the [180;200[ range
	 */
	bool isRingingSomewhere() const;

protected:
	void onPushSent(PushNotificationContext& aPNCtx, bool aRingingPush) noexcept override;

	void start() override;
	void onNewRegister(const SipUri& dest,
	                   const std::string& uid,
	                   const std::shared_ptr<ExtendedContact>& newContact) override;
	void onResponse(const std::shared_ptr<BranchInfo>& br, ResponseSipEvent& event) override;
	const char* getClassName() const override;

private:
	struct CancelInfo {
		CancelInfo(sofiasip::Home& home, const ForkStatus& status);
		CancelInfo(sip_reason_t* reason);

		ForkStatus mStatus;
		sip_reason_t* mReason{};
	};

	static constexpr std::string_view kClassName{"ForkCallContext"};
	static constexpr int kUrgentCodesWithout603[] = {401, 407, 415, 420, 484, 488, 606, 0};

	ForkCallContext(std::unique_ptr<RequestSipEvent>&& event,
	                sofiasip::MsgSipPriority priority,
	                const std::weak_ptr<ForkContextListener>& forkContextListener,
	                const std::weak_ptr<InjectorListener>& injectorListener,
	                AgentInterface* agent,
	                const std::shared_ptr<ForkContextConfig>& config,
	                const std::weak_ptr<StatPair>& counter);

	void onLateTimeout() override;
	bool shouldFinish() override;

	/**
	 * @return the list of SIP status codes that are considered as urgent regarding the configuration of this fork
	 */
	const int* getUrgentCodes();
	/**
	 * @brief Send urgent responses to branches if no branch is ringing.
	 */
	void onShortTimer();
	/**
	 * @brief Cancel all branches when at least one branch has been answered with a final response.
	 *
	 * @param br the branch that received the CANCEL request
	 */
	void cancelOthers(const std::shared_ptr<BranchInfo>& br);
	/**
	 * @brief Cancel all branches.
	 *
	 * @param received_cancel CANCEL request received
	 */
	void cancelAll(const sip_t* received_cancel);
	/**
	 * @brief Cancel all branches with a specific status.
	 *
	 * @param br the branch that received the CANCEL request
	 * @param status the status
	 */
	void cancelOthersWithStatus(const std::shared_ptr<BranchInfo>& br, ForkStatus status);
	/**
	 * @brief Send the event log for this response.
	 *
	 * @param ev received response
	 */
	void logResponse(const std::unique_ptr<ResponseSipEvent>& ev, const BranchInfo*);
	/**
	 * @brief Forward the response on the provided branch and send an event log for this response.
	 */
	void forwardThenLogResponse(const std::shared_ptr<BranchInfo>&);
	/**
	 * @param brit branch to cancel
	 */
	void cancelBranch(const std::shared_ptr<BranchInfo>& brit);

	sofiasip::Home mHome{};
	// Optionally used to send retryable responses.
	std::unique_ptr<sofiasip::Timer> mShortTimer{};
	std::shared_ptr<CallLog> mLog{};
	bool mCancelled{};
	std::optional<CancelInfo> mCancel{};
	std::string mLogPrefix{};
};

} // namespace flexisip