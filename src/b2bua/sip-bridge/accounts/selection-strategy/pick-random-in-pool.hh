/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "account-selection-strategy.hh"

namespace flexisip::b2bua::bridge::account_strat {

class PickRandomInPool : public AccountSelectionStrategy {
public:
	PickRandomInPool(std::shared_ptr<AccountPool> accountPool) : AccountSelectionStrategy(accountPool) {
	}

	std::shared_ptr<Account> chooseAccountForThisCall(const linphone::Call&) const override {
		return getAccountPool().getAccountRandomly();
	}
};

} // namespace flexisip::b2bua::bridge::account_strat
