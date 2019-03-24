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

#include "flexisip/expressionparser.hh"

#include <cstring>
#include <sstream>
#include <algorithm>

#include <regex.h>


using namespace std;

namespace flexisip{



template <typename _valuesT>
class ConstantBooleanExpression : public BooleanExpression<_valuesT> {
  public:
	EmptyBooleanExpression(bool ret) : mRet(ret){};
	virtual bool eval(const _valuesT &args) override{
		return mRet;
	}
	bool mRet;
};

template <typename _valuesT>
class LogicalAnd : public BooleanExpression<_valuesT> {
private:
	using Expr = BooleanExpression<_valuesT>;
	shared_ptr<Expr> mExp1, mExp2;
 public:
	LogicalAnd(const shared_ptr<Expr> &exp1, const shared_ptr<Expr> &exp2) : mExp1(exp1), mExp2(exp2) {};
	virtual bool eval(const _valuesT &args) override{
		return mExp1->eval(args) && mExp2->eval(args);
	}
};

template <typename _valuesT>
class LogicalOr : public BooleanExpression<_valuesT> {
  public:
	using Expr = BooleanExpression<_valuesT>;
	LogicalOr(const shared_ptr<Expr> &exp1, const shared_ptr<Expr> &exp2) : mExp1(exp1), mExp2(exp2) {
	}
	virtual bool eval(const _valuesT &args) override{
		return mExp1->eval(args) || mExp2->eval(args);
	}
  private:
	shared_ptr<Expr> mExp1, mExp2;
};

template <typename _valuesT>
class LogicalNot : public BooleanExpression<_valuesT> {
  public:
	using Expr = BooleanExpression<_valuesT>;
	LogicalNot(const shared_ptr<Expr> &exp) : mExp(exp) {
	}
	virtual bool eval(const _valuesT &args) override{
		return !mExp->eval(args);
	}

  private:
	shared_ptr<BooleanExpression> mExp;
};

template <typename _valuesT>
class EqualsOp : public BooleanExpression<_valuesT> {
  public:
	using Var = Variable<_valuesT>;
	EqualsOp(const shared_ptr<Var> &var1, const shared_ptr<Var> &var2) : mVar1(var1), mVar2(var2) {
	}
	virtual bool eval(const _valuesT &args) override{
		return mVar1->get(args) == mVar2->get(args);
	}
  private:
	shared_ptr<Var> mVar1, mVar2;
};

template <typename _valuesT>
class UnEqualsOp : public BooleanExpression<_valuesT> {
  public:
	using Var = Variable<_valuesT>;
	UnEqualsOp(const shared_ptr<Var> &var1, const shared_ptr<Var> &var2) : mVar1(var1), mVar2(var2) {
	}
	virtual bool eval(const _valuesT &args) override{
		return mVar1->get(args) != mVar2->get(args);
	}
  private:
	shared_ptr<Var> mVar1, mVar2;
};

/*
 * This operator evaluates whether a variable is purely numeric or not.
 */
template <typename _valuesT>
class NumericOp : public BooleanExpression<_valuesT>{
public:
	using Var = Variable<_valuesT>;
	NumericOp(const shared_ptr<Var> &var) : mVar(var) {
	}
	virtual bool eval(const _valuesT &args) override{
		string var = mVar->get(args);
		bool res = true;
		for (auto it = var.begin(); it != var.end(); ++it) {
			if (!isdigit(*it)) {
				res = false;
				break;
			}
		}
		return res;
	}
private:
	shared_ptr<Var> mVar;
};

/*
 * This operator returns true if the variable is defined in the context of provided _valuesT.
 * It directly uses the defined() method of variable to do this.
 */
template <typename _valuesT>
class DefinedOp : public BooleanExpression<_valuesT> {
public:
	using Var = Variable<_valuesT>;
	DefinedOp(const shared_ptr<Var> &var) : mVar(var) {
	}
	virtual bool eval(const _valuesT &args) {
		return mVar->defined(args);
	}
private:
	shared_ptr<VariableOrConstant> mVar;
};

template <typename _valuesT>
class RegexpOp : public BooleanExpression<_valuesT> {
public:
	using Var = Variable<_valuesT>;
	RegexpOp(const shared_ptr<Var> &input, const shared_ptr<Constant<_valuesT>> &pattern) : mInput(input) {
		string p = pattern->get();
		int err = regcomp(&preg, p.c_str(), REG_NOSUB | REG_EXTENDED);
		if (err != 0)
			throw invalid_argument("couldn't compile regex " + p);
	}
	~RegexpOp() {
		regfree(&preg);
	}
	virtual bool eval(const _valuesT &args) {
		string input = mInput->get(args);
		int match = regexec(&preg, input.c_str(), 0, NULL, 0);
		bool res = false;
		switch (match) {
			case 0:
				res = true;
				break;
			case REG_NOMATCH:
				res = false;
				break;
			default:
			{
				char error_msg_buff[100] = {0};
				regerror(match, &preg, error_msg_buff, sizeof(error_msg_buff)-1);
				LOGE("RegexpOp error: %s", error_msg_buff);
			}
		}
		return res;
	}
private:
	shared_ptr<Var> mInput;
	regex_t preg;
	
};

template <typename _valuesT>
class ContainsOp : public BooleanExpression {
public:
	using Var = Variable<_valuesT>;
	ContainsOp(const shared_ptr<Var> &var1, const shared_ptr<Var> &var2) : mVar1(var1), mVar2(var2) {
	}
	virtual bool eval(const _valuesT &args) override{
		string var1 = mVar1->get(args);
		string var2 = mVar2->get(args);
		return var1.find(var2) != string::npos;
	}
private:
	shared_ptr<Var> mVar1, mVar2;
};

/*
 * Evaluates whether a variable has its value equal to an element of a list of other variables.
 */
template <typename _valuesT>
class InOp : public BooleanExpression {
public:
	using Var = Variable<_valuesT>;
	InOp(const shared_ptr<Var> &var1, const shared_ptr<Var> &var2) : mVar1(var1), mVar2(var2) {
	}
	virtual bool eval(const _valuesT &args) {
		bool res = false;
		list<string> values = mVar2->getAsList(args);
		string varValue = mVar1->get(args);

		for (auto it = values.begin(); it != values.end(); ++it) {
			if (varValue == *it) {
				res = true;
				break;
			}
		}
		return res;
	}
private:
	shared_ptr<VariableOrConstant> mVar1, mVar2;
};

static size_t find_first_non_word(const string &expr, size_t offset) {
	size_t i;
	for (i = offset; i < expr.size(); ++i) {
		char c = expr[i];
		if (c != '-' && c != '.' && !isalnum(c))
			return i;
	}
	return i;
}

static shared_ptr<Variable> buildVariable(const string &expr, size_t *newpos) {
	LOGPARSE << "buildVariable working on XX" << expr << "XX";
	while (expr[*newpos] == ' ')
		*newpos += 1;

	size_t eow = find_first_non_word(expr, *newpos);
	if (eow <= *newpos && expr.size() > eow) {
		throw invalid_argument("no variable recognized in X" + expr.substr(*newpos, string::npos) + "XX");
	}
	size_t len = eow - *newpos;
	auto var = expr.substr(*newpos, len);
	*newpos += len;
	return make_shared<Variable>(var);
}

static shared_ptr<Constant> buildConstant(const string &expr, size_t *newpos) {
	LOGPARSE << "buildConstant working on XX" << expr << "XX";
	while (expr[*newpos] == ' ')
		*newpos += 1;

	if (expr[*newpos] != '\'')
		throw invalid_argument("Missing quote at start of " + expr);

	size_t end = expr.find_first_of('\'', *newpos + 1);
	if (end != string::npos) {
		size_t len = end - *newpos - 1;
		auto cons = expr.substr(*newpos + 1, len);
		*newpos += len + 2; // remove the two '
		return make_shared<Constant>(cons);
	} else {
		throw invalid_argument("Missing quote around " + expr);
	}
}

static shared_ptr<VariableOrConstant> buildVariableOrConstant(const string &expr, size_t *newpos) {
	LOGPARSE << "buildVariableOrConstant working on XX" << expr << "XX";
	while (expr[*newpos] == ' ')
		*newpos += 1;

	if (expr[*newpos] == '\'') {
		auto constant = buildConstant(expr, newpos);
		return dynamic_pointer_cast<VariableOrConstant>(constant);
	} else {
		auto variable = buildVariable(expr, newpos);
		return dynamic_pointer_cast<VariableOrConstant>(variable);
	}
}

static size_t findMatchingClosingParenthesis(const string &expr, size_t offset) {
	size_t i;
	int match = 1;
	for (i = offset; i < expr.size(); ++i) {
		if (expr[i] == '(')
			++match;
		else if (expr[i] == ')')
			--match;
		if (match == 0)
			return i;
	}
	return string::npos;
}

static bool isKeyword(const string &expr, size_t *newpos, const string &keyword) {
	size_t pos = *newpos;
	size_t keyLen = keyword.size();
	size_t availableLen = expr.size() - pos;
	if (availableLen < keyLen)
		return false;

	for (size_t i = 0; i < keyLen; ++i) {
		if (expr[pos + i] != keyword[i])
			return false;
	}

	if (availableLen > keyLen && isalnum(expr[pos + keyLen]))
		return false;

	*newpos += keyLen;
	LOGPARSE << "Recognized keyword '" << keyword << "'";
	return true;
}

template< typename _valuesT>
std::shared_ptr<BooleanExpression<_valuesT>> BooleanExpressionBuilder::parse(const std::string &expression){
	if (expression.empty())
		return make_shared<ConstantBooleanExpression<_valuesT>>(true); /* By arbitrary decision, we evaluate void to true.*/
	size_t pos = 0;
	auto expr = parseExpression(str, &pos);
	return expr;
}

template< typename _valuesT>
const std::list<std::string> BooleanExpressionBuilder<_valuesT>::sBuiltinOperators = {
	"&&", "||", "!", "==", "contains", "in", "notin", "nin", "defined", "regexp", "regex", "numeric",
	"true", "false"
};

template< typename _valuesT>
shared_ptr<Expr> BooleanExpressionBuilder::parseExpression(const string &expr, size_t *newpos) {
	size_t i;
	shared_ptr<Expr> cur_exp;
	shared_ptr<Var> cur_var;

	for (i = 0; i < expr.size();) {
		size_t j = 0;
		size_t prev_i = i;
		switch (expr[i]) {
			case '(': {
				size_t end = findMatchingClosingParenthesis(expr, i + 1);
				if (end != string::npos) {
					cur_exp = parseExpression(expr.substr(i + 1, end - i - 1), &j);
					i = end + 1;
				} else {
					throw invalid_argument("Missing parenthesis around " + expr);
				}
			} break;
			case '&':
				if (expr[i + 1] == '&') {
					if (!cur_exp) {
						throw new logic_error("&& operator expects first operand.");
					}
					i += 2;
					cur_exp = make_shared<LogicalAnd<_valuesT>>(cur_exp, parseExpression(expr.substr(i), &j));
					i += j;
				} else {
					throw new logic_error("Bad operator '&'");
				}
				break;
			case '|':
				if (expr[i + 1] == '|') {
					if (!cur_exp) {
						throw new logic_error("|| operator expects first operand.");
					}
					i += 2;
					cur_exp = make_shared<LogicalOr<_valuesT>>(cur_exp, parseExpression(expr.substr(i), &j));
					i += j;
				} else {
					throw invalid_argument("Bad operator '|'");
				}
				break;
			case '!':
				if (expr[i + 1] == '=') {
					if (!cur_var) {
						throw invalid_argument("!= operator expects first variable or const operand.");
					}
					i += 2;
					cur_exp = make_shared<UnEqualsOp<_valuesT>>(cur_var, buildVariableOrConstant(expr.substr(i), &j));
				} else {
					if (cur_exp) {
						throw invalid_argument("Parsing error around '!'");
					}
					i++;
					cur_exp = make_shared<LogicalNot<_valuesT>>(parseExpression(expr.substr(i), &j);
				}
				i += j;
				break;
			case '=':
				if (expr[i + 1] == '=') {
					if (!cur_var) {
						throw invalid_argument("== operator expects first variable or const operand.");
					}
					i += 2;
					cur_exp = make_shared<EqualsOp<_valuesT>>(cur_var, buildVariableOrConstant(expr.substr(i), &j));
					i += j;
				} else {
					throw invalid_argument("Bad operator =");
				}
				break;
			case ' ':
				i++;
				break;
			case 'c':
				if (isKeyword(expr.substr(i), &j, "contains")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<ContainsOp<_valuesT>>(cur_var, rightVar);
					i += j;
				}
				break;
			case 'd':
				if (isKeyword(expr.substr(i), &j, "defined")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<DefinedOp>(expr.substr(i, j), rightVar);
					i += j;
				}
				break;
			case 'r':
				if (isKeyword(expr.substr(i), &j, "regexp") || isKeyword(expr.substr(i), &j, "regex")) {
					i += j;
					j = 0;
					auto pattern = buildConstant(expr.substr(i), &j);
					cur_exp = make_shared<RegexpOp<_valuesT>>(cur_var, pattern);
					i += j;
				}
				break;
			case 'i':
				if (isKeyword(expr.substr(i), &j, "in")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<InOp>(cur_var, rightVar);
					i += j;
				}
				break;
			case 'n':
				if (isKeyword(expr.substr(i), &j, "numeric")) {
					if (cur_exp || cur_var) {
						throw invalid_argument("Parsing error around 'numeric'");
					}
					i += j;
					j = 0;
					auto var = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<NumericOp<_valuesT>>(var);
					i += j;
					j = 0;
				} else if (isKeyword(expr.substr(i), &j, "nin") || isKeyword(expr.substr(i), &j, "notin")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					auto in = make_shared<InOp<_valuesT>>(cur_var, rightVar);
					cur_exp = make_shared<LogicalNot<_valuesT>>(in);
					i += j;
				}
				break;
			case 't':
				if (isKeyword(expr.substr(i), &j, "true")) {
					i += j;
					cur_exp = make_shared<ConstantBooleanExpression<_valuesT>>(true);
				}
				break;
			case 'f':
				if (isKeyword(expr.substr(i), &j, "false")) {
					i += j;
					cur_exp = make_shared<ConstantBooleanExpression<_valuesT>>(false);
				}
				break;
			default:
				break;
		}
		if (prev_i == i){ /*nothing was handled*/
			cur_var = buildVariableOrConstant(expr.substr(i), &j);
			i += j;
		}
	}
	*newpos += i;
	return cur_exp;
};

rajouter  is_resquest, is_response

if (isKeyword(expr.substr(i), &(j = 0), "true")) {
						i += j;
						j = 0;
						cur_exp = make_shared<TrueFalseExpression>("true");
					} else if (isKeyword(expr.substr(i), &(j = 0), "false")) {
						i += j;
						j = 0;
						cur_exp = make_shared<TrueFalseExpression>("false");
					} else if (isKeyword(expr.substr(i), &(j = 0), "numeric")) {
						i += j;
						j = 0;
						auto var = buildVariableOrConstant(expr.substr(i), &j);
						cur_exp = make_shared<NumericOp>(var);
					} else if (isKeyword(expr.substr(i), &j, "defined")) {
						i += j;
						j = 0;
						auto var = buildVariableOrConstant(expr.substr(i), &j);
						cur_exp = make_shared<DefinedOp>(expr.substr(i, j), var);
					} else if (expr[i] == '(') {
						size_t end = find_matching_closing_parenthesis(expr, i + 1);
						if (end != string::npos) {
							cur_exp = parseExpression(expr.substr((i + 1), end - (i + 1)), &j);
							i = end + 1;
							j = 0; // no use
						} else {
							throw invalid_argument("Missing parenthesis around " + expr);
						}
					} else {
						ostringstream oss;
						oss << expr[i];
						LOGPARSE << ">" << oss.str();
						throw invalid_argument("! operator expects boolean value or () expression.");
					}

std::shared_ptr<BooleanExpression> BooleanExpression::parse(const std::string &str) {
	
}


