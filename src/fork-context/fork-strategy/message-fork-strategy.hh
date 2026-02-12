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
#include <string_view>

#include "flexisip/event.hh"
#include "fork-context/branch-info.hh"
#include "fork-context/fork-context.hh"
#include "fork-context/message-kind.hh"
#include "fork-strategy.hh"

namespace flexisip {

class MessageForkStrategy : public IForkStrategy {
public:
	MessageForkStrategy(const MessageKind& kind, bool isRestored, const std::shared_ptr<ForkContextConfig>& config);
	~MessageForkStrategy() override;

	std::shared_ptr<const EventLogWriteDispatcher>
	makeStartEventLog(const MsgSip& msgSip, const std::list<std::shared_ptr<BranchInfo>>& branches) override;
	OnResponseAction chooseActionOnResponse(const std::shared_ptr<BranchInfo>& br) override;
	bool shouldFinish() override {
		return true;
	}
	ResponseStrategy chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>& br) override;
	ResponseStrategy chooseStrategyOnDecisionTimer() override;
	ResponseStrategy chooseStrategyOnLateTimeout() override;
	std::pair<int, const char*> getDefaultResponse() const override;
	void logResponse(const std::shared_ptr<BranchInfo>& branch,
	                 RequestSipEvent& request,
	                 ResponseSipEvent& response) override;
	void logSentResponse(const std::unique_ptr<ResponseSipEvent>& respEv,
	                     const BranchInfo*,
	                     RequestSipEvent& reqEv) const override;
	void updateBranch(const std::shared_ptr<BranchInfo>&, RequestSipEvent&) override {}

	bool shouldAcceptNextBranches() const override;
	bool mayAcceptNewRegister(const SipUri& dest,
	                          const std::string& uid,
	                          const std::shared_ptr<ExtendedContact>& newContact) override;
	bool shouldAcceptDispatch(const std::shared_ptr<BranchInfo>& br, const std::string& uid) override;
	void onDispatch(const std::shared_ptr<BranchInfo>&) override {}
	void onNewBranch(const std::shared_ptr<BranchInfo>& br) override;

	void onInternalError() override {}
	void onCancel(const MsgSip&) override;

	const std::string_view getStrategyName() const override {
		return kStrategyName;
	}

	time_t getExpirationDate() const {
		return mExpirationDate;
	}
	void setExpirationDate(time_t expirationDate) {
		mExpirationDate = expirationDate;
	}
	int getDeliveredCount() const {
		return mDeliveredCount;
	}
	void setDeliveredCount(int count) {
		mDeliveredCount = count;
	}

private:
	static constexpr std::string_view kStrategyName = "Message";
	static constexpr std::string_view kEventIdHeader{"X-fs-event-id"};
	/**
	 * @brief Send the event log for this response to the recipient.
	 *
	 * @param br branch that received the response
	 * @param respEv received response
	 */
	void logResponseFromRecipient(const BranchInfo& br, ResponseSipEvent& respEv);

	int mDeliveredCount;
	// Type of SIP MESSAGE this context is handling.
	MessageKind mKind;
	std::shared_ptr<ForkContextConfig> mCfg;
	// Used in fork late mode with a message saved in DB to remember the message expiration date.
	time_t mExpirationDate;
	std::string mLogPrefix;
};
} // namespace flexisip