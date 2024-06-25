/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
	std::shared_ptr<Account> chooseAccountForThisEvent(const linphone::Event&) const override;

private:
	const AccountPool::IndexedView& mAccountView;
	utils::string_interpolation::TemplateFormatter<const linphone::Call&> mSourceTemplate;
	utils::string_interpolation::TemplateFormatter<const linphone::Event&> mEventSourceTemplate;
};

} // namespace flexisip::b2bua::bridge::account_strat
