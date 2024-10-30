/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <linphone++/call.hh>

#include "b2bua/sip-bridge/accounts/account-pool.hh"

namespace flexisip::b2bua::bridge::account_strat {

class AccountSelectionStrategy {
public:
	explicit AccountSelectionStrategy(const std::shared_ptr<AccountPool>& accountPool) : mAccountPool(accountPool) {
	}
	virtual ~AccountSelectionStrategy() = default;

	virtual std::shared_ptr<Account> chooseAccountForThisCall(const linphone::Call&) const = 0;
	virtual std::shared_ptr<Account> chooseAccountForThisTransfer(const linphone::Call&) const = 0;
	virtual std::shared_ptr<Account> chooseAccountForThisEvent(const linphone::Event&) const = 0;

	const AccountPool& getAccountPool() const {
		return *mAccountPool;
	}

protected:
	std::shared_ptr<AccountPool> mAccountPool;
};

} // namespace flexisip::b2bua::bridge::account_strat