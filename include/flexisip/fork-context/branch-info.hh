/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <memory>

#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/registrardb.hh"
#include "flexisip/transaction.hh"

namespace flexisip {

class BranchInfo {
public:
	template <typename T> BranchInfo(T&& ctx) : mForkCtx{std::forward<T>(ctx)} {
	}

	void clear() {
		mTransaction.reset();
		mRequest.reset();
		mLastResponse.reset();
		mForkCtx.reset();
	}

	int getStatus() {
		return mLastResponse ? mLastResponse->getMsgSip()->getSip()->sip_status->st_status : 0;
	}

	// Obtain the BranchInfo corresponding to an outgoing transaction
	static std::shared_ptr<BranchInfo> getBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr) {
		return tr->getProperty<BranchInfo>("BranchInfo");
	}

	// Set the BranchInfo managed by an outoing transaction
	static void setBranchInfo(const std::shared_ptr<OutgoingTransaction>& tr, const std::weak_ptr<BranchInfo> br) {
		tr->setProperty("BranchInfo", br);
	}

	std::weak_ptr<ForkContext> mForkCtx{};
	std::string mUid{};
	std::shared_ptr<RequestSipEvent> mRequest{};
	std::shared_ptr<OutgoingTransaction> mTransaction{};
	std::shared_ptr<ResponseSipEvent> mLastResponse{};
	std::shared_ptr<ExtendedContact> mContact{};
	float mPriority{1.0f};
	bool mPushSent{false}; // Whether  push notification has been sent for this branch.
};

} // namespace flexisip
