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

#include <regex>

#include "b2bua/sip-bridge/configuration/v2/v2.hh"
#include "linphone++/call.hh"

namespace flexisip::b2bua::bridge::trigger_strat {

namespace conf = config::v2::trigger_cond;

class TriggerStrategy {
public:
	virtual ~TriggerStrategy() = default;

	virtual bool shouldHandleThisCall(const linphone::Call&) = 0;
	virtual bool shouldHandleThisEvent(const linphone::Event&) = 0;
};

class Always : public TriggerStrategy {
public:
	bool shouldHandleThisCall(const linphone::Call&) override {
		return true;
	}
	bool shouldHandleThisEvent(const linphone::Event&) override {
		return true;
	}
};

class MatchRegex : public TriggerStrategy {
public:
	MatchRegex(const conf::MatchRegex&);

	bool shouldHandleThisCall(const linphone::Call&) override;
	bool shouldHandleThisEvent(const linphone::Event&) override;

private:
	std::regex mPattern;
};

} // namespace flexisip::b2bua::bridge::trigger_strat