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
#include <memory>
#include <string>
#include <cstring>
#include <sstream>
#include <iostream>
#include <map>
#include <list>
#include <tuple>
#include <stdexcept>
#include <algorithm>
#include "expressionparser.hh"
#include "sipattrextractor.hh"

#include <regex.h>

#include <flexisip/logmanager.hh>
#include "utils/flexisip-exception.hh"

using namespace std;
using namespace flexisip;

static string tf(bool value) {
	return value ? "true" : "false";
}

BooleanExpression::~BooleanExpression() {
}

long BooleanExpression::ptr() {
	return (long)this;
}

#ifndef NO_SOFIA
bool BooleanExpression::eval(const sip_t *sip) {
	bool result;
	try {
		SipAttributes attr(sip);
		result = eval(&attr);
	} catch (std::exception& e) {
		throw FLEXISIP_EXCEPTION << "Cannot evaluate boolean expression  for " << sip << " : " << e.what();
	}
	return result;
}
#endif

class EmptyBooleanExpression : public BooleanExpression {
  public:
	EmptyBooleanExpression() {
	}
	bool eval(const SipAttributes *args) {
		return true;
	}
};

shared_ptr<BooleanExpression> parseExpression(const string &expr, size_t *newpos);

/*
 * May return empty expression
 */
std::shared_ptr<BooleanExpression> BooleanExpression::parse(const std::string &str) {
	if (str.empty())
		return make_shared<EmptyBooleanExpression>();
	size_t pos = 0;
	auto expr = parseExpression(str, &pos);
	return expr;
}

static bool logEval = false;
void log_boolean_expression_evaluation(bool value) {
	logEval = value;
}

static bool logParse = false;
void log_boolean_expression_parsing(bool value) {
	logParse = value;
}

#define LOGPARSE                                                                                                       \
	if (logParse)                                                                                                      \
	SLOGI
#define LOGEVAL                                                                                                        \
	if (logEval)                                                                                                       \
	SLOGI

class VariableOrConstant {
	list<string> mValueList;

  public:
	virtual ~VariableOrConstant() {
	}
	virtual const std::string &get(const SipAttributes *args) = 0;
	bool defined(const SipAttributes *args) {
		try {
			get(args);
			return true;
		} catch (exception &) {
		}
		return false;
	}
	const list<string> &getAsList(const SipAttributes *args) {
		string s = get(args);
		mValueList.clear();

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
			mValueList.push_back(s.substr(pos1, pos2 - pos1));
			pos1 = pos2;
		}

		if (pos1 != pos2)
			mValueList.push_back(s.substr(pos1, pos2 - pos1));

		return mValueList;
	}
};

class Constant : public VariableOrConstant {
	string mVal;

  public:
	Constant(const std::string &val) : mVal(val) {
		LOGPARSE << "Creating constant XX" << val << "XX";
	}
	virtual const std::string &get(const SipAttributes *args) {
		return mVal;
	}
};

class Variable : public VariableOrConstant {
	string mId;
	string mVal;

  public:
	Variable(const std::string &val) : mId(val) {
		LOGPARSE << "Creating variable XX" << val << "XX";
	}
	virtual const std::string &get(const SipAttributes *args) {
		mVal = args->get(mId);
		return mVal;
	}
};

class TrueFalseExpression : public BooleanExpression {
	string mId;

  public:
	TrueFalseExpression(const string &value) : mId(value) {
	}
	virtual bool eval(const SipAttributes *args) {
		if (mId == "true")
			return true;
		if (mId == "false")
			return false;
		return args->isTrue(mId);
	}
};

class LogicalAnd : public BooleanExpression {
	shared_ptr<BooleanExpression> mExp1, mExp2;

  public:
	LogicalAnd(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2) : mExp1(exp1), mExp2(exp2) {
		LOGPARSE << "Creating LogicalAnd";
	}
	virtual bool eval(const SipAttributes *args) {
		LOGEVAL << "eval && : " << ptr();
		bool e1 = mExp1->eval(args);
		LOGEVAL << "eval && : " << ptr() << "left exp =" << tf(e1);
		bool res = e1 && mExp2->eval(args);
		LOGEVAL << "eval && : " << ptr() << tf(res);
		return res;
	}
};

class LogicalOr : public BooleanExpression {
  public:
	LogicalOr(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2) : mExp1(exp1), mExp2(exp2) {
		LOGPARSE << "Creating LogicalOr";
	}
	virtual bool eval(const SipAttributes *args) {
		LOGEVAL << "eval || : " << ptr();
		bool e1 = mExp1->eval(args);
		LOGEVAL << "eval || : " << ptr() << "left exp =" << tf(e1);

		bool res = e1 || mExp2->eval(args);
		LOGEVAL << "eval || : " << tf(res);
		return res;
	}

  private:
	shared_ptr<BooleanExpression> mExp1, mExp2;
};

class LogicalNot : public BooleanExpression {
  public:
	LogicalNot(shared_ptr<BooleanExpression> exp) : mExp(exp) {
		LOGPARSE << "Creating LogicalNot";
	}
	virtual bool eval(const SipAttributes *args) {
		bool res = !mExp->eval(args);
		LOGEVAL << "evaluating logicalnot : " << (res ? "true" : "false");
		return res;
	}

  private:
	shared_ptr<BooleanExpression> mExp;
};

class EqualsOp : public BooleanExpression {
  public:
	EqualsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2) {
		LOGPARSE << "Creating EqualsOperator";
	}
	virtual bool eval(const SipAttributes *args) {
		bool res = mVar1->get(args) == mVar2->get(args);
		LOGEVAL << "evaluating " << mVar1->get(args) << " == " << mVar2->get(args) << " : " << (res ? "true" : "false");
		return res;
	}

  private:
	shared_ptr<VariableOrConstant> mVar1, mVar2;
};

class UnEqualsOp : public BooleanExpression {
  public:
	UnEqualsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2) {
		LOGPARSE << "Creating UnEqualsOperator";
	}
	virtual bool eval(const SipAttributes *args) {
		bool res = mVar1->get(args) != mVar2->get(args);
		LOGEVAL << "evaluating " << mVar1->get(args) << " != " << mVar2->get(args) << " : " << (res ? "true" : "false");
		return res;
	}

  private:
	shared_ptr<VariableOrConstant> mVar1, mVar2;
};

class NumericOp : public BooleanExpression {
	shared_ptr<VariableOrConstant> mVar;

  public:
	NumericOp(shared_ptr<VariableOrConstant> var) : mVar(var) {
		LOGPARSE << "Creating NumericOperator";
	}
	virtual bool eval(const SipAttributes *args) {
		string var = mVar->get(args);
		bool res = true;
		for (auto it = var.begin(); it != var.end(); ++it) {
			if (!isdigit(*it)) {
				res = false;
				break;
			}
		}
		LOGEVAL << "evaluating " << var << " is numeric : " << (res ? "true" : "false");
		return res;
	}
};

class DefinedOp : public BooleanExpression {
	shared_ptr<VariableOrConstant> mVar;
	string mName;

  public:
	DefinedOp(string name, shared_ptr<VariableOrConstant> var) : mVar(var), mName(name) {
		LOGPARSE << "Creating DefinedOperator";
	}
	virtual bool eval(const SipAttributes *args) {
		bool res = mVar->defined(args);
		LOGEVAL << "evaluating is defined for " << mName << (res ? "true" : "false");
		return res;
	}
};

class Regex : public BooleanExpression {
	shared_ptr<VariableOrConstant> mInput;
	shared_ptr<Constant> mPattern;
	regex_t preg;
	char error_msg_buff[100];

  public:
	Regex(shared_ptr<VariableOrConstant> input, shared_ptr<Constant> pattern) : mInput(input), mPattern(pattern) {
		LOGPARSE << "Creating Regular Expression";
		string p = pattern->get(NULL);
		int err = regcomp(&preg, p.c_str(), REG_NOSUB | REG_EXTENDED);
		if (err != 0)
			throw invalid_argument("couldn't compile regex " + p);
	}
	~Regex() {
		regfree(&preg);
	}
	virtual bool eval(const SipAttributes *args) {
		string input = mInput->get(args);
		int match = regexec(&preg, input.c_str(), 0, NULL, 0);
		bool res;
		switch (match) {
			case 0:
				res = true;
				break;
			case REG_NOMATCH:
				res = false;
				break;
			default:
				regerror(match, &preg, error_msg_buff, sizeof(error_msg_buff));
				throw invalid_argument("Error evaluating regex " + string(error_msg_buff));
		}

		LOGEVAL << "evaluating " << input << " is regex  " << mPattern->get(NULL) << " : " << (res ? "true" : "false");
		return res;
	}
};

class ContainsOp : public BooleanExpression {
	shared_ptr<VariableOrConstant> mVar1, mVar2;

  public:
	ContainsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2) {
	}
	virtual bool eval(const SipAttributes *args) {
		bool res = false;
		try {
			string var1 = mVar1->get(args);
			string var2 = mVar2->get(args);
			res = var1.find(var2) != std::string::npos;

			LOGEVAL << "evaluating " << mVar1->get(args) << " contains " << mVar2->get(args) << " : "
			<< (res ? "true" : "false");
		} catch (invalid_argument &e) {
			// We allow to use "contains()" with empty arguments, which returns always false instead of bubbling an exception.
			SLOGE << "Exception: Some arguments were missing (" << e.what() << "): return false";
			return false;
		}
		// we could get a runtime_error, which we let bubble up because this error denotes a badly written filter (instead of just a missing field in the SIP message.
		return res;
	}
};

class InOp : public BooleanExpression {
  public:
	InOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2) {
	}
	virtual bool eval(const SipAttributes *args) {
		bool res = false;
		const list<string> &values = mVar2->getAsList(args);
		const string &varValue = mVar1->get(args);

		LOGEVAL << "Evaluating '" << varValue << "' IN {" << mVar2->get(args) << "}";
		for (auto it = values.begin(); it != values.end(); ++it) {
			LOGEVAL << "Trying '" << *it << "'";
			if (varValue == *it) {
				res = true;
				break;
			}
		}
		LOGEVAL << "->" << (res ? "true" : "false");
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

static size_t find_matching_closing_parenthesis(const string &expr, size_t offset) {
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

static void printState(const string &str, size_t pos) {
	LOGPARSE << "Working on " << str;
	ostringstream oss;
	for (size_t i = 0; i < pos + 11; ++i)
		oss << " ";
	oss << "^";
	if (pos < str.size()) {
		oss << str.substr(pos, 1);
	}
	LOGPARSE << oss.str().c_str();
}

shared_ptr<BooleanExpression> parseExpression(const string &expr, size_t *newpos) {
	size_t i;

	LOGPARSE << "Parsing expression " << expr;
	shared_ptr<BooleanExpression> cur_exp;
	shared_ptr<VariableOrConstant> cur_var;

	for (i = 0; i < expr.size();) {
		size_t j = 0;
		printState(expr, *newpos + i);
		switch (expr[i]) {
			case '(': {
				size_t end = find_matching_closing_parenthesis(expr, i + 1);
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
					cur_exp = make_shared<LogicalAnd>(cur_exp, parseExpression(expr.substr(i), &j));
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
					cur_exp = make_shared<LogicalOr>(cur_exp, parseExpression(expr.substr(i), &j));
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
					cur_exp = make_shared<UnEqualsOp>(cur_var, buildVariableOrConstant(expr.substr(i), &j));
				} else {
					if (cur_exp) {
						throw invalid_argument("Parsing error around '!'");
					}
					i++;
					for (; expr[i] == ' '; ++i)
						; // skip spaces (we are fair)

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

					// Take the negation!
					cur_exp = make_shared<LogicalNot>(cur_exp);
				}
				i += j;
				break;
			case '=':
				if (expr[i + 1] == '=') {
					if (!cur_var) {
						throw invalid_argument("== operator expects first variable or const operand.");
					}
					i += 2;
					cur_exp = make_shared<EqualsOp>(cur_var, buildVariableOrConstant(expr.substr(i), &j));
					i += j;
				} else {
					throw invalid_argument("Bad operator =");
				}
				break;
			case ' ':
				LOGPARSE << "skipping space";
				i++;
				break;
			case 'c':
				if (isKeyword(expr.substr(i), &j, "contains")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<ContainsOp>(cur_var, rightVar);
					i += j;
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
				}
				break;
			case 'd':
				if (isKeyword(expr.substr(i), &j, "defined")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<DefinedOp>(expr.substr(i, j), rightVar);
					i += j;
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
				}
				break;
			case 'r':
				if (isKeyword(expr.substr(i), &j, "regex")) {
					i += j;
					j = 0;
					auto pattern = buildConstant(expr.substr(i), &j);
					cur_exp = make_shared<Regex>(cur_var, pattern);
					i += j;
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
				}
				break;
			case 'i':
				if (isKeyword(expr.substr(i), &j, "in")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					cur_exp = make_shared<InOp>(cur_var, rightVar);
					i += j;
				} else if (isKeyword(expr.substr(i), &j, "is_request")) {
					i += j;
					j = 0;
					cur_exp = make_shared<TrueFalseExpression>("is_request");
				} else if (isKeyword(expr.substr(i), &j, "is_response")) {
					i += j;
					j = 0;
					cur_exp = make_shared<TrueFalseExpression>("is_response");
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
				}
				break;
			case 't':
				if (isKeyword(expr.substr(i), &j, "true")) {
					i += j;
					j = 0;
					cur_exp = make_shared<TrueFalseExpression>("true");
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
				}
				break;
			case 'f':
				if (isKeyword(expr.substr(i), &j, "false")) {
					i += j;
					j = 0;
					cur_exp = make_shared<TrueFalseExpression>("false");
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
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
					cur_exp = make_shared<NumericOp>(var);
					i += j;
					j = 0;
					// fixme should check all is finished now
				} else if (isKeyword(expr.substr(i), &j, "nin") || isKeyword(expr.substr(i), &j, "notin")) {
					i += j;
					j = 0;
					auto rightVar = buildVariableOrConstant(expr.substr(i), &j);
					auto in = make_shared<InOp>(cur_var, rightVar);
					cur_exp = make_shared<LogicalNot>(in);
					i += j;
				} else {
					cur_var = buildVariableOrConstant(expr.substr(i), &j);
					i += j;
					j = 0;
				}
				break;
			default:
				cur_var = buildVariableOrConstant(expr.substr(i), &j);
				i += j;
				j = 0;
				break;
		}
	}
	*newpos += i;
	return cur_exp;
};
