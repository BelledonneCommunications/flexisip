/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "trigger-strategy.hh"

#include <regex>

#include <linphone++/address.hh>

namespace flexisip::b2bua::bridge::trigger_strat {

MatchRegex::MatchRegex(const conf::MatchRegex& config) : mPattern(config.pattern) {
	// TODO(jabiru): Allow matching on other fields of the incoming call, not just the request URI
}

bool MatchRegex::shouldHandleThisCall(const linphone::Call& call) {
	return std::regex_match(call.getRequestAddress()->asStringUriOnly(), mPattern);
}

bool MatchRegex::shouldHandleThisEvent(const linphone::Event& event) {
	return std::regex_match(event.getResource()->asStringUriOnly(), mPattern);
}

} // namespace flexisip::b2bua::bridge::trigger_strat
