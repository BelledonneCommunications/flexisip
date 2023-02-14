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


#include <string>
#include <memory>
#include <map>
#include <list>
#include <functional>


namespace flexisip {


class ExpressionElement{
public:
	virtual ~ExpressionElement() = default;
};
	
/* 
 * Variable represents a text field which is evaluated at run-time using the _valuesT argument.
 */
template <typename _valuesT>
class Variable : public ExpressionElement{
public:
	Variable(const std::function< std::string (const _valuesT &)> &func) : mFunc(func){
	}
	~Variable() = default;
	virtual std::string get(const _valuesT &args){
		return mFunc(args);
	}
	virtual bool defined(const _valuesT &args){
		if (get(args).empty()) return false;
		return true;
	}
	virtual std::list<std::string> getAsList(const _valuesT &args) {
		std::list<std::string> valueList;
		std::string s = get(args);
		
		size_t pos1 = 0;
		size_t pos2 = 0;
		for (pos2 = 0; pos2 < s.size(); ++pos2) {
			if (s[pos2] != ' ') {
				if (s[pos1] == ' ')
					pos1 = pos2;
				continue;
			}
			if (s[pos2] == ' ' && s[pos1] == ' ') {
				pos1 = pos2;
				continue;
			}
			valueList.push_back(s.substr(pos1, pos2 - pos1));
			pos1 = pos2;
		}

		if (pos1 != pos2)
			valueList.push_back(s.substr(pos1, pos2 - pos1));

		return valueList;
	}
private:
	std::function< std::string (const _valuesT &)> mFunc;
protected:
	Variable() = default;
};

/*
 * Constant can be seen as a special kind of variable that always evaluates to the same thing, regardless of _valuesT argument contains.
 * They are enclosed by single quotes in the boolean expression.
 */
template <typename _valuesT>
class Constant : public Variable<_valuesT>{
	std::string mVal;
  public:
	Constant(const std::string &val) : Variable<_valuesT>(), mVal(val) {
	}
	virtual std::string get([[maybe_unused]] const _valuesT &arg) override{
		return mVal;
	}
	std::string get()const{
		return mVal;
	}
};


/*
 * Base class for our boolean expression.
 * It contains the factory method to create BooleanExpression from an input string,
 * and the eval() method to evaluates the BooleanExpression to true or false according
 * to supplied _valuesT arguments.
 */
template <typename _valuesT>
class BooleanExpression {
 public:
	virtual ~BooleanExpression() = default;
	virtual bool eval(const _valuesT &args) = 0;
protected:
	BooleanExpression() = default;
};


/*
 * A named operator is a function that evaluates on the values provided to return
 * true or false.
 */
template <typename _valuesT>
class NamedOperator : public BooleanExpression<_valuesT>, public ExpressionElement{
public:
	NamedOperator(const std::function< bool (const _valuesT &)> func) : mFunc(func){
	}
	virtual bool eval(const _valuesT &args) override{
		return mFunc(args);
	}
private:
	std::function< bool (const _valuesT &)> mFunc;
};

/*
 * The ExpressionRules consist of two maps suitable to be initialized with builtin initializers.
 * The variables map provides mapping between a variable name and function to be called to get the
 * variable's value in the _valuesT argument.
 * The operators map provides the mapping between operator names and the function that evaluates them.
 */

template <typename _valuesT>
struct ExpressionRules{
public:
	std::map<std::string, std::function< std::string (const _valuesT &)>> variables; // the map of variables with their function to evaluate
	std::map<std::string, std::function< bool (const _valuesT &)>> operators; // the named operators, with their function to evaluate.
};

/*
 * The BooleanExpressionBuilder creates BooleanExpression by parsing an input string.
 * The BooleanExpression is constructed according to the rules provided in the constructor,
 * which gave the map of allowed variables and named operators.
 */
template <typename _valuesT>
class BooleanExpressionBuilder{
public:
	using Var = Variable<_valuesT>;
	using Const = Constant<_valuesT>;
	using Expr = BooleanExpression<_valuesT>;
	BooleanExpressionBuilder(const ExpressionRules<_valuesT> &rules);
	std::shared_ptr<BooleanExpression<_valuesT>> parse(const std::string &expression);
private:
	void checkRulesOverlap();
	size_t findFirstNonWord(const std::string &expr, size_t offset);
	size_t findMatchingClosingParenthesis(const std::string &expr, size_t offset);
	bool isKeyword(const std::string &expr, size_t *newpos, const std::string &keyword);
	std::shared_ptr<Var> buildVariable(const std::string &expr, size_t *newpos);
	std::shared_ptr<Const> buildConstant(const std::string &expr, size_t *newpos);
	std::shared_ptr<ExpressionElement> buildElement(const std::string &expr, size_t *newpos);
	std::shared_ptr<Expr> parseExpression(const std::string &expr, size_t *newpos, bool immediateNeighbour = false);
	const ExpressionRules<_valuesT> mRules;
	static const std::list<std::string> sBuiltinOperators;
};


}

