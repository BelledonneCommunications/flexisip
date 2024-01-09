/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include "account-selection-strategy.hh"

#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "utils/string-interpolation/preprocessed-interpolated-string.hh"

namespace flexisip::b2bua::bridge::account_strat {

class FindInPool : public AccountSelectionStrategy {
public:
	explicit FindInPool(std::shared_ptr<AccountPool>, const config::v2::account_selection::FindInPool&);

	std::shared_ptr<Account> chooseAccountForThisCall(const linphone::Call&) const override;

private:
	config::v2::account_selection::AccountLookUp mLookUpField;
	utils::string_interpolation::PreprocessedInterpolatedString<const linphone::Call&> mSourceTemplate;
};

} // namespace flexisip::b2bua::bridge::account_strat
