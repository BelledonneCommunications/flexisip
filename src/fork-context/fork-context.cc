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

#include "fork-context.hh"

#include "agent.hh"
#include "branch-info.hh"
#include "transaction/incoming-transaction.hh"
#include "transaction/outgoing-transaction.hh"

using namespace std;
using namespace flexisip;

shared_ptr<ForkContext> ForkContext::getFork(const shared_ptr<IncomingTransaction>& transaction) {
	return transaction->getProperty<ForkContext>("ForkContext");
}

shared_ptr<ForkContext> ForkContext::getFork(const shared_ptr<OutgoingTransaction>& transaction) {
	shared_ptr<BranchInfo> br = BranchInfo::getBranchInfo(transaction);
	return br ? br->mForkCtx.lock() : nullptr;
}

void ForkContext::setFork(const shared_ptr<IncomingTransaction>& transaction, const shared_ptr<ForkContext>& context) {
	transaction->setProperty<ForkContext>("ForkContext", weak_ptr<ForkContext>{context});
}

void ForkContext::processCancel(RequestSipEvent& ev) {
	auto transaction = dynamic_pointer_cast<IncomingTransaction>(ev.getIncomingAgent());

	if (transaction && ev.getMsgSip()->getSip()->sip_request->rq_method == sip_method_cancel) {
		auto ctx = ForkContext::getFork(transaction);

		if (ctx) {
			ctx->onCancel(*ev.getMsgSip());
			ev.terminateProcessing();
		}
	}
}

bool ForkContext::processResponse(ResponseSipEvent& ev) {
	auto transaction = dynamic_pointer_cast<OutgoingTransaction>(ev.getOutgoingAgent());
	if (transaction) {
		auto bInfo = BranchInfo::getBranchInfo(transaction);
		// If not, responses has not been processed.
		if (bInfo) {
			bInfo->mLastResponseEvent = make_unique<ResponseSipEvent>(ev); // make a copy
			bInfo->mLastResponse = bInfo->mLastResponseEvent->getMsgSip();

			bInfo->mLastResponseEvent->suspendProcessing();

			auto forkCtx = bInfo->mForkCtx.lock();
			forkCtx->onResponse(bInfo, *bInfo->mLastResponseEvent);

			// the event may go through but it will not be sent*/
			ev.setIncomingAgent(nullptr);

			// A response has been submitted, else, it has been retained.
			if (!bInfo->mLastResponseEvent || !bInfo->mLastResponseEvent->isSuspended()) {
				// mLastResponseEvent has been resubmitted, so stop original event.
				ev.terminateProcessing();
			}

			if (forkCtx->allCurrentBranchesAnswered(FinalStatusMode::RFC) && forkCtx->hasNextBranches()) {
				forkCtx->start();
			}

			return true;
		}
	}

	return false;
}