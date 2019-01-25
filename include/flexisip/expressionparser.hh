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

#ifndef NO_SOFIA
#include <sofia-sip/sip.h>
#endif

#include <string>
#include <memory>
#include <flexisip/flexisip-exception.hh>

void log_boolean_expression_evaluation(bool value);
void log_boolean_expression_parsing(bool value);

namespace flexisip {

class SipAttributes;

class BooleanExpression {
  protected:
	BooleanExpression() {
	}

  public:
#ifndef NO_SOFIA
	bool eval(const sip_t *sip);
#endif
	virtual bool eval(const SipAttributes *args) = 0;
	virtual ~BooleanExpression();
	static std::shared_ptr<BooleanExpression> parse(const std::string &str);
	long ptr();
};

}