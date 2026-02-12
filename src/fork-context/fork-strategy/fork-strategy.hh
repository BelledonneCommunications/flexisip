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

#include "eventlogs/events/event-log-write-dispatcher.hh"
#include "flexisip/event.hh"
#include "fork-context/branch-info.hh"

namespace flexisip {
enum class OnResponseAction { Wait, WaitAndUpdate, Send, SendAndUpdate };
enum class ResponseStrategy { Wait, Best, Default, BestElseDefault };

class IForkStrategy {
public:
	virtual ~IForkStrategy() = default;
	virtual std::shared_ptr<const EventLogWriteDispatcher>
	makeStartEventLog(const MsgSip&, const std::list<std::shared_ptr<BranchInfo>>&) = 0;
	virtual OnResponseAction chooseActionOnResponse(const std::shared_ptr<BranchInfo>& br) = 0;
	virtual bool shouldFinish() = 0;
	virtual ResponseStrategy chooseStrategyOnceAllBranchesAnswered(const std::shared_ptr<BranchInfo>&) = 0;
	virtual ResponseStrategy chooseStrategyOnDecisionTimer() = 0;
	virtual ResponseStrategy chooseStrategyOnLateTimeout() = 0;
	virtual std::pair<int, const char*> getDefaultResponse() const = 0;

	virtual void logResponse(const std::shared_ptr<BranchInfo>&, RequestSipEvent&, ResponseSipEvent&) = 0;
	virtual void logSentResponse(const std::unique_ptr<ResponseSipEvent>& respEv,
	                             const BranchInfo* br,
	                             RequestSipEvent& reqEv) const = 0;
	virtual void updateBranch(const std::shared_ptr<BranchInfo>&, RequestSipEvent&) = 0;

	// onNextBranches
	virtual bool shouldAcceptNextBranches() const = 0;
	// onNewRegister
	virtual bool mayAcceptNewRegister(const SipUri& dest,
	                                  const std::string& uid,
	                                  const std::shared_ptr<ExtendedContact>& newContact) = 0;
	virtual bool shouldAcceptDispatch(const std::shared_ptr<BranchInfo>&, const std::string&) = 0;
	virtual void onDispatch(const std::shared_ptr<BranchInfo>&) = 0;

	virtual void onNewBranch(const std::shared_ptr<BranchInfo>&) = 0;

	virtual void onInternalError() = 0;
	virtual void onCancel(const MsgSip&) = 0;
	virtual const std::string_view getStrategyName() const = 0;
	// hack for voicemail
	virtual void setForkContext(const std::shared_ptr<ForkContext>&){};
};
} // namespace flexisip