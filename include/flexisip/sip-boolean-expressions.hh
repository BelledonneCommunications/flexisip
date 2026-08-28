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

using sip_t = struct sip_s;

namespace flexisip {

class SipBooleanExpression : public BooleanExpression<sip_t> {
public:
	explicit SipBooleanExpression(const std::shared_ptr<BooleanExpression<sip_t>>& expression)
	    : mExpression(expression) {}

	SipBooleanExpression(const std::shared_ptr<BooleanExpression<sip_t>>& expression, const std::string& name)
	    : mExpression(expression), mName(name) {}

	/**
	 * @warning If no name provided (at construction time of the object), no log message will be produced.
	 * @returns the result of evaluating the boolean expression and logs a message if the result is false.
	 */
	bool eval(const sip_t& sip) override;

	const std::string& getName() const {
		return mName;
	}

	/**
	 * Disable logging for this expression.
	 * After calling this method, no log message will be produced when the expression evaluates to false.
	 */
	void disableLogging() {
		mName.clear();
	}

private:
	std::shared_ptr<BooleanExpression<sip_t>> mExpression;
	std::string mName;
};

class SipBooleanExpressionBuilder : public BooleanExpressionBuilder<sip_t> {
public:
	static SipBooleanExpressionBuilder& get();

	/**
	 * @param expression The boolean expression to parse.
	 * @param name The name of the expression (usually configuration parameter name), used for logging purposes.
	 */
	std::shared_ptr<SipBooleanExpression> parse(const std::string& expression, const std::string& name = {});

private:
	SipBooleanExpressionBuilder();
	static std::shared_ptr<SipBooleanExpressionBuilder> sInstance;
};

} // namespace flexisip
