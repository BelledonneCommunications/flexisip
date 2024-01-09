/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <regex>

#include <linphone++/call.hh>

#include "b2bua/sip-bridge/configuration/v2/v2.hh"

namespace flexisip::b2bua::bridge::trigger_strat {

namespace conf = flexisip::b2bua::bridge::config::v2::trigger_cond;

class TriggerStrategy {
public:
	virtual ~TriggerStrategy() = default;

	virtual bool shouldHandleThisCall(const linphone::Call&) = 0;
};

class Always : public TriggerStrategy {
public:
	bool shouldHandleThisCall(const linphone::Call&) override {
		return true;
	}
};

class MatchRegex : public TriggerStrategy {
public:
	MatchRegex(const conf::MatchRegex&);

	bool shouldHandleThisCall(const linphone::Call&) override;

private:
	std::regex mPattern;
};

} // namespace flexisip::b2bua::bridge::trigger_strat
