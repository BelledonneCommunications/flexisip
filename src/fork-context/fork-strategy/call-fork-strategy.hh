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

#include <optional>
#include <string_view>

#include "eventlogs/events/eventlogs.hh"
#include "flexisip/event.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/call-step.hh"
#include "fork-context/fork-context.hh"
#include "fork-context/fork-status.hh"
#include "fork-strategy.hh"

namespace flexisip {
/**
 * @brief Handle the forking of SIP calls (INVITE requests).
 */
class CallForkStrategy : public IForkStrategy {
public:
	CallForkStrategy(RequestSipEvent& event,
	                 const std::shared_ptr<ForkContextConfig>& config,
	                 CallStep callStep = CallStep::Initial);
	~CallForkStrategy() override;

	std::shared_ptr<const EventLogWriteDispatcher>
	makeStartEventLog(const MsgSip& msgSip, const std::list<std::shared_ptr<BranchInfo>>& branches) override;
	OnResponseAction chooseActionOnResponse(const std::shared_ptr<BranchInfo>& br) override;
	ResponseStrategy chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>& best) override;
	ResponseStrategy chooseStrategyOnDecisionTimer() override;
	ResponseStrategy chooseStrategyOnLateTimeout() override;
	std::pair<int, const char*> getDefaultResponse() const override;
	void logResponse(const std::shared_ptr<BranchInfo>& branch,
	                 RequestSipEvent& request,
	                 ResponseSipEvent& response) override;
	void logSentResponse(const std::unique_ptr<ResponseSipEvent>& repEv,
	                     const BranchInfo* branch,
	                     RequestSipEvent& reqEv) const override;
	void updateBranch(const std::shared_ptr<BranchInfo>& branch, RequestSipEvent& request) override;

	bool shouldAcceptNextBranches() const override;
	bool mayAcceptNewRegister(const SipUri& dest,
	                          const std::string& uid,
	                          const std::shared_ptr<ExtendedContact>& newContact) override;
	bool shouldAcceptDispatch(const std::shared_ptr<BranchInfo>& branch, const std::string& uid) override;
	void onDispatch(const std::shared_ptr<BranchInfo>& dispatched) override;
	void onNewBranch(const std::shared_ptr<BranchInfo>&) override {}

	void onInternalError() override;
	void onCancel(const MsgSip& ms) override;

	const std::string_view getStrategyName() const override {
		return kStrategyName;
	}

private:
	static constexpr std::string_view kStrategyName = "Call";

	/**
	 * @brief Set cancel when a CANCEL request is received.
	 *
	 * @param received_cancel CANCEL request received
	 */
	void cancelWithMessage(const sip_t* received_cancel);
	/**
	 * @brief Set cancel with a specific status.
	 *
	 * @param status the status
	 */
	void cancelWithStatus(ForkStatus status);
	/**
	 * @return 'true' if the fork process is terminated
	 */
	bool isCompleted() const;
	/**
	 * @return the list of SIP status codes that are considered as urgent regarding the configuration of this fork
	 */
	const int* getUrgentCodes() const;

	sofiasip::Home mHome{};
	std::shared_ptr<CallLog> mLog{};
	bool mCancelled{};
	std::optional<CancelInfo> mCancel{};
	bool mStopping{};
	std::shared_ptr<ForkContextConfig> mCfg;
	CallStep mCallStep{CallStep::Initial};
	std::string mLogPrefix{};

	enum class UrgentCodeState { DoNotForward, AwaitingBetterResponse, SendOnReceived };
	UrgentCodeState mUrgentCode{UrgentCodeState::DoNotForward};
};

} // namespace flexisip