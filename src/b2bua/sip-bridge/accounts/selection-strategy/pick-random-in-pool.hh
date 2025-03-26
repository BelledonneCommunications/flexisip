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

#include "account-selection-strategy.hh"

namespace flexisip::b2bua::bridge::account_strat {

class PickRandomInPool : public AccountSelectionStrategy {
public:
	PickRandomInPool(const std::shared_ptr<AccountPool>& accountPool) : AccountSelectionStrategy(accountPool) {
	}

	std::shared_ptr<Account> chooseAccountForThisCall(const linphone::Call&) const override {
		return getAccountPool().getAccountRandomly();
	}
	std::shared_ptr<Account> chooseAccountForThisTransfer(const linphone::Call&) const override {
		LOGW << "Strategy is not implemented for call transfers yet: undefined behavior";
		return getAccountPool().getAccountRandomly();
	}
	std::shared_ptr<Account> chooseAccountForThisEvent(const linphone::Event&) const override {
		return getAccountPool().getAccountRandomly();
	}

private:
	static constexpr std::string_view mLogPrefix{"PickRandomInPool"};
};

} // namespace flexisip::b2bua::bridge::account_strat