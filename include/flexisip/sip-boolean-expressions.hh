/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010  Belledonne Communications SARL.

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

#include "flexisip/expressionparser.hh"

typedef struct sip_s sip_t;

namespace flexisip{

typedef BooleanExpression<sip_t> SipBooleanExpression;

class SipBooleanExpressionBuilder : public BooleanExpressionBuilder<sip_t>{
public:
	static SipBooleanExpressionBuilder &get();
	std::shared_ptr<SipBooleanExpression> parse(const std::string &expression);
private:
	SipBooleanExpressionBuilder();
	static std::shared_ptr<SipBooleanExpressionBuilder> sInstance;
};

}//end of namespace
