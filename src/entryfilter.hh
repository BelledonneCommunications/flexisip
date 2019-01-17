/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <list>
#include <string>
#include <memory>
#include "expressionparser.hh"

#include <flexisip/agent.hh>

/**
 * The goal of this object is to filter SIP message that enter into a module.
 **/
class EntryFilter {
  public:
	virtual void declareConfig(GenericStruct *module_config) {
	}
	virtual void loadConfig(const GenericStruct *module_config) {
	}
	virtual bool canEnter(const std::shared_ptr<MsgSip> &ms) = 0;
	virtual bool isEnabled() = 0;
	virtual ~EntryFilter() {
	}
};

class ConfigEntryFilter : public EntryFilter {
	StatCounter64 *mCountEvalTrue;
	StatCounter64 *mCountEvalFalse;

  public:
	ConfigEntryFilter();
	virtual ~ConfigEntryFilter();
	virtual void declareConfig(GenericStruct *module_config);
	virtual void loadConfig(const GenericStruct *module_config);
	virtual bool canEnter(const std::shared_ptr<MsgSip> &ms);
	virtual bool isEnabled();

  private:
	bool mEnabled;
	std::shared_ptr<BooleanExpression> mBooleanExprFilter;
	std::string mEntryName;
};