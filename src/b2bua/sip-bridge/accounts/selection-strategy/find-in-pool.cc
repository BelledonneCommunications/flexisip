/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <utility>

#include "find-in-pool.hh"

#include "b2bua/sip-bridge/string-format-fields.hh"

namespace flexisip::b2bua::bridge::account_strat {
using namespace utils::string_interpolation;
using namespace std::string_literals;

FindInPool::FindInPool(const std::shared_ptr<AccountPool>& accountPool,
                       const config::v2::account_selection::FindInPool& config)
    : AccountSelectionStrategy(accountPool), mAccountView(mAccountPool->getOrCreateView([&] {
	      // Backward compat.: This field was previously an enum of
	      // "uri" | "alias"
	      if (config.by == "uri") return "{uri}"s;
	      else if (config.by == "alias") return "{alias}"s;
	      else return config.by;
      }())),
      mSourceTemplate(config.source, kLinphoneCallFields),
      mEventSourceTemplate(config.source, kLinphoneEventFields) {
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisCall(const linphone::Call& incomingCall) const {
	const auto& source = mSourceTemplate.format(incomingCall);

	const auto& [formatter, view] = mAccountView;
	auto log = SLOGD;
	log << "FindInPool strategy attempted to find an account matching " << formatter.getTemplate() << " == '" << source
	    << "' for call '" << incomingCall.getCallLog()->getCallId() << "': ";

	const auto maybeAccount = view.find(source);
	if (maybeAccount == view.end()) {
		log << "not found";
		return {};
	}

	const auto& account = maybeAccount->second;
	log << "found '" << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString();
	return account;
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisEvent(const linphone::Event& incomingEvent) const {
	const auto& source = mEventSourceTemplate.format(incomingEvent);

	const auto& [formatter, view] = mAccountView;
	auto log = SLOGD;
	log << "FindInPool strategy attempted to find an account matching " << formatter.getTemplate() << " == '" << source
	    << "' for SUBSCRIBE: ";

	const auto maybeAccount = view.find(source);
	if (maybeAccount == view.end()) {
		log << "not found";
		return {};
	}

	const auto& account = maybeAccount->second;
	log << "found '" << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString();
	return account;
}

} // namespace flexisip::b2bua::bridge::account_strat
