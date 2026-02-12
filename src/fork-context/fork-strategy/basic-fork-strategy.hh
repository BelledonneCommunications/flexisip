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
#include <string>
#include <string_view>

#include "flexisip/event.hh"
#include "fork-context/branch-info.hh"
#include "fork-strategy.hh"

namespace flexisip {

class BasicForkStrategy : public IForkStrategy {
public:
	BasicForkStrategy();
	~BasicForkStrategy() override;

	std::shared_ptr<const EventLogWriteDispatcher>
	makeStartEventLog(const MsgSip&, const std::list<std::shared_ptr<BranchInfo>>&) override {
		return {};
	}
	OnResponseAction chooseActionOnResponse(const std::shared_ptr<BranchInfo>& br) override;
	bool shouldFinish() override {
		return true;
	}
	ResponseStrategy chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>&) override;
	ResponseStrategy chooseStrategyOnDecisionTimer() override;
	ResponseStrategy chooseStrategyOnLateTimeout() override;
	std::pair<int, const char*> getDefaultResponse() const override;
	void logResponse(const std::shared_ptr<BranchInfo>&, RequestSipEvent&, ResponseSipEvent&) override {}
	void logSentResponse(const std::unique_ptr<ResponseSipEvent>&, const BranchInfo*, RequestSipEvent&) const override {
	}
	void updateBranch(const std::shared_ptr<BranchInfo>&, RequestSipEvent&) override {}

	bool shouldAcceptNextBranches() const override;
	// BasicStrategy does nothing onNewRegister
	bool mayAcceptNewRegister(const SipUri&, const std::string&, const std::shared_ptr<ExtendedContact>&) override {
		return false;
	}
	bool shouldAcceptDispatch(const std::shared_ptr<BranchInfo>&, const std::string&) override {
		return false;
	}
	void onDispatch(const std::shared_ptr<BranchInfo>&) override {}
	void onNewBranch(const std::shared_ptr<BranchInfo>&) override {}

	void onInternalError() override {}
	void onCancel(const MsgSip&) override;

	const std::string_view getStrategyName() const override {
		return kStrategyName;
	}

private:
	static constexpr std::string_view kStrategyName = "Basic";
	std::string mLogPrefix;
};

} // namespace flexisip