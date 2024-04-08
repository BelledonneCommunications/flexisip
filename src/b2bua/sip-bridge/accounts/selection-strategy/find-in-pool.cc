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
      mSourceTemplate(InterpolatedString(config.source, "{", "}"), resolve(kLinphoneCallFields)),
      mEventSourceTemplate(InterpolatedString(config.source, "{", "}"), resolve(kLinphoneEventFields)) {
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisCall(const linphone::Call& incomingCall) const {
	using namespace variable_substitution;
	const auto& source = mSourceTemplate.format(incomingCall);

	auto log = pumpstream(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_DEBUG);
	log << "FindInPool strategy attempted to find an account with a(n) " << nlohmann::json(mLookUpField)
	    << " matching '" << source << "' for call '" << incomingCall.getCallLog()->getCallId() << "': ";

	auto account = chooseAccount(source);
	if (account == nullptr) {
		log << "not found";
	} else {
		log << "found '" << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString();
	}

	return account;
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisEvent(const linphone::Event& incomingEvent) const {
	const auto& source = mEventSourceTemplate.format(incomingEvent);

	auto log = pumpstream(FLEXISIP_LOG_DOMAIN, BCTBX_LOG_DEBUG);
	log << "FindInPool strategy attempted to find an account with a(n) " << nlohmann::json(mLookUpField)
	    << " matching '" << source << "' for SUBSCRIBE: ";

	auto account = chooseAccount(source);
	if (account == nullptr) {
		log << "not found";
	} else {
		log << "found '" << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString();
	}

	return account;
}

std::shared_ptr<Account> FindInPool::chooseAccount(const std::string& source) const {
	const auto& pool = getAccountPool();
	std::shared_ptr<Account> account;

	switch (mLookUpField) {
		using namespace config::v2::account_selection;
		case AccountLookUp::ByUri: {
			account = pool.getAccountByUri(source);
		} break;
		case AccountLookUp::ByAlias: {
			account = pool.getAccountByAlias(source);
		} break;
		default: {
			throw std::logic_error{"Missing case statement"};
		} break;
	};

	return account;
}

} // namespace flexisip::b2bua::bridge::account_strat
