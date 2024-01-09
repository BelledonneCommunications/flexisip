/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "find-in-pool.hh"

#include "b2bua/sip-bridge/variable-substitution.hh"

namespace flexisip::b2bua::bridge::account_strat {
using namespace utils::string_interpolation;
using namespace variable_substitution;

FindInPool::FindInPool(std::shared_ptr<AccountPool> accountPool,
                       const config::v2::account_selection::FindInPool& config)
    : AccountSelectionStrategy(accountPool), mLookUpField(config.by),
      mSourceTemplate(InterpolatedString(config.source, "{", "}"), resolve(kLinphoneCallFields)) {
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisCall(const linphone::Call& incomingCall) const {
	using namespace variable_substitution;
	const auto& source = mSourceTemplate.format(incomingCall);
	const auto& pool = getAccountPool();

	auto log = pumpstream(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_DEBUG);
	log << "FindInPool strategy attempted to find an account with a(n) " << nlohmann::json(mLookUpField)
	    << " matching '" << source << "' for call '" << incomingCall.getCallLog()->getCallId() << "': ";

	std::shared_ptr<Account> maybeAccount;
	switch (mLookUpField) {
		using namespace config::v2::account_selection;
		case AccountLookUp::ByUri: {
			maybeAccount = pool.getAccountByUri(source);
		} break;
		case AccountLookUp::ByAlias: {
			maybeAccount = pool.getAccountByAlias(source);
		} break;
		default: {
			throw std::logic_error{"Missing case statement"};
		} break;
	};

	if (maybeAccount == nullptr) {
		log << "not found";
	} else {
		log << "found '" << maybeAccount->getLinphoneAccount()->getParams()->getIdentityAddress()->asString();
	}

	return maybeAccount;
}

} // namespace flexisip::b2bua::bridge::account_strat
