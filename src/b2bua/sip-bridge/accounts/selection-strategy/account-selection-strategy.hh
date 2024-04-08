/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <linphone++/call.hh>

#include "b2bua/sip-bridge/accounts/account-pool.hh"

namespace flexisip::b2bua::bridge::account_strat {

class AccountSelectionStrategy {
public:
	explicit AccountSelectionStrategy(std::shared_ptr<AccountPool> accountPool) : mAccountPool(accountPool) {
	}
	virtual ~AccountSelectionStrategy() = default;

	virtual std::shared_ptr<Account> chooseAccountForThisCall(const linphone::Call&) const = 0;
	virtual std::shared_ptr<Account> chooseAccountForThisEvent(const linphone::Event&) const = 0;

	const AccountPool& getAccountPool() const {
		return *mAccountPool;
	}

private:
	std::shared_ptr<AccountPool> mAccountPool;
};

} // namespace flexisip::b2bua::bridge::account_strat
