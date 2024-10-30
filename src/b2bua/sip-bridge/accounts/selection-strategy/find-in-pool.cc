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

#include "find-in-pool.hh"

#include "b2bua/sip-bridge/string-format-fields.hh"

namespace flexisip::b2bua::bridge::account_strat {
using namespace std;
using namespace utils::string_interpolation;
using namespace std::string_literals;

FindInPool::FindInPool(const std::shared_ptr<AccountPool>& accountPool,
                       const config::v2::account_selection::FindInPool& config)
    : AccountSelectionStrategy(accountPool), mAccountView(mAccountPool->getOrCreateView([&] {
	      // Backward compatibility: this field was previously an enum of "uri" | "alias"
	      if (config.by == "uri") return "{uri}"s;
	      else if (config.by == "alias") return "{alias}"s;
	      else return config.by;
      }())),
      mSourceTemplate(config.source, kLinphoneCallFields),
      mTransferSourceTemplate(config.source, kLinphoneCallTransferFields),
      mEventSourceTemplate(config.source, kLinphoneEventFields) {
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisCall(const linphone::Call& incomingCall) const {
	const string event{"call (" + incomingCall.getCallLog()->getCallId() + ")"};
	return findAccountMatching(mSourceTemplate.format(incomingCall), event);
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisTransfer(const linphone::Call& call) const {
	const string event{"call (" + call.getCallLog()->getCallId() + ") transfer"};
	return findAccountMatching(mTransferSourceTemplate.format(call), event);
}

std::shared_ptr<Account> FindInPool::chooseAccountForThisEvent(const linphone::Event& incomingEvent) const {
	return findAccountMatching(mEventSourceTemplate.format(incomingEvent), incomingEvent.getName());
}

std::shared_ptr<Account> FindInPool::findAccountMatching(const std::string& source, std::string_view event) const {
	const auto& [formatter, view] = mAccountView;
	auto log = SLOGD;
	log << "FindInPool strategy attempted to find an account matching " << formatter.getTemplate() << " == '" << source
	    << "' for " << event << ": ";

	const auto maybeAccount = view.find(source);
	if (maybeAccount == view.end()) {
		log << "not found";
		return {};
	}

	const auto& account = maybeAccount->second;
	log << "found '" << account->getLinphoneAccount()->getParams()->getIdentityAddress()->asString() << "'";
	return account;
}

} // namespace flexisip::b2bua::bridge::account_strat