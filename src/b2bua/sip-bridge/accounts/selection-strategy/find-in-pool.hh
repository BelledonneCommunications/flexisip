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
#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "utils/string-interpolation/template-formatter.hh"

namespace flexisip::b2bua::bridge::account_strat {

class FindInPool : public AccountSelectionStrategy {
public:
	explicit FindInPool(const std::shared_ptr<AccountPool>&, const config::v2::account_selection::FindInPool&);

	std::shared_ptr<Account> chooseAccountForThisCall(const linphone::Call&) const override;
	std::shared_ptr<Account> chooseAccountForThisTransfer(const linphone::Call&) const override;
	std::shared_ptr<Account> chooseAccountForThisEvent(const linphone::Event&) const override;

private:
	static constexpr std::string_view mLogPrefix{"FindInPool"};

	std::shared_ptr<Account> findAccountMatching(const std::string& source, std::string_view event) const;

	const AccountPool::IndexedView& mAccountView;
	utils::string_interpolation::TemplateFormatter<const linphone::Call&> mSourceTemplate;
	utils::string_interpolation::TemplateFormatter<const linphone::Call&> mTransferSourceTemplate;
	utils::string_interpolation::TemplateFormatter<const linphone::Event&> mEventSourceTemplate;
};

} // namespace flexisip::b2bua::bridge::account_strat