/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <list>
#include <memory>
#include <string>

#include "flexisip/configmanager.hh"
#include "flexisip/expressionparser.hh"

namespace flexisip {

/**
 * The goal of this object is to filter SIP message that enter into a module.
 **/
class EntryFilter {
public:
	virtual void declareConfig([[maybe_unused]] GenericStruct* module_config) {
	}
	virtual void loadConfig([[maybe_unused]] const GenericStruct* module_config) {
	}
	virtual bool canEnter(const std::shared_ptr<MsgSip>& ms) = 0;
	virtual bool isEnabled() = 0;
	virtual ~EntryFilter() = default;
};

class ConfigEntryFilter : public EntryFilter {
	StatCounter64* mCountEvalTrue = nullptr;
	StatCounter64* mCountEvalFalse = nullptr;

public:
	ConfigEntryFilter() = default;
	void declareConfig(GenericStruct* module_config) override;
	void loadConfig(const GenericStruct* module_config) override;
	bool canEnter(const std::shared_ptr<MsgSip>& ms) override;
	bool isEnabled() override;

private:
	bool mEnabled = false;
	std::shared_ptr<SipBooleanExpression> mBooleanExprFilter;
	std::string mEntryName;
};

} // namespace flexisip
