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

#include "trigger-strategy.hh"

#include <regex>

#include "linphone++/address.hh"
#include "linphone++/event.hh"

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