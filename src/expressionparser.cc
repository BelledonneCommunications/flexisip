
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

#include <regex.h>

#ifndef TEST_BOOL_EXPR
#include "common.hh"
#endif


using namespace::std;


static string tf(bool value) {
	return value?"true":"false";
}

string BooleanExpression::ptr() {
	ostringstream oss;
	oss << (long)this;
	return oss.str();
}

class EmptyBooleanExpression : public BooleanExpression {
public:
	EmptyBooleanExpression() {}
	bool eval(const Arguments *args) { return true; }
};

shared_ptr<BooleanExpression> parseExpression(const string & expr, size_t *newpos);

/*
 * May return empty expression
 */
std::shared_ptr<BooleanExpression> BooleanExpression::parse(const std::string &str) {
	if (str.empty()) return make_shared<EmptyBooleanExpression>();
	size_t pos=0;
	auto expr = parseExpression(str, &pos);
	return expr;
}

static bool logEval=false;
void log_boolean_expression_evaluation(bool value) { logEval=value; }

static bool logParse=false;
void log_boolean_expression_parsing(bool value) { logParse=value; }

static void log(initializer_list<string> tuple) {
	if (!logParse) return;
#ifdef TEST_BOOL_EXPR
	for (auto it=tuple.begin(); it != tuple.end(); ++it) {
		cout << *it;
	}
	cout << endl;
#else
	if (IS_LOGD) {
		ostringstream oss;
		for (auto it=tuple.begin(); it != tuple.end(); ++it) {
			oss << *it;
		}
		LOGD("%s", oss.str().c_str());
	}
#endif
}





class VariableOrConstant {
	list<string> mValueList;
public:
	virtual ~VariableOrConstant() {};
	virtual const std::string &get(const Arguments *args)=0;
	const bool defined(const Arguments *args) {
		try {
			get(args);
			return true;
		} catch (exception *e) {}
		return false;
	}
	const list<string> &getAsList(const Arguments *args) {
		string s=get(args);
		mValueList.clear();

		size_t pos1=0;
		size_t pos2=0;
		for (pos2=0; pos2 < s.size(); ++pos2) {
			if (s[pos2] != ' ') {
				if (s[pos1] == ' ') pos1=pos2;
				continue;
			}
			if (s[pos2] == ' ' && s[pos1] == ' ') {
				pos1=pos2;
				continue;
			}
			mValueList.push_back(s.substr(pos1, pos2-pos1));
			pos1=pos2;
		}

		if (pos1 != pos2)
			mValueList.push_back(s.substr(pos1, pos2-pos1));

		return mValueList;
	}
};

class Constant : public VariableOrConstant {
	string mVal;
public:
	Constant(const std::string &val): mVal(val) {
		log({"Creating constant XX", val, "XX"});
	}
	virtual const std::string &get(const Arguments *args) {
		return mVal;
	}
};

class Variable : public VariableOrConstant {
	string mId;
	string mVal;
public:
	Variable(const std::string &val): mId(val) {
		log({"Creating variable XX", val, "XX"});
	}
	virtual const std::string &get(const Arguments *args) {
		try {
			mVal=args->get(mId);
		} catch (exception *e) {
			log({"GET ", mId, " : ", e->what()});
			throw;
		}
		return mVal;
	}
};

class TrueFalseExpression : public BooleanExpression {
	string mId;
public:
	TrueFalseExpression(const string &value) : mId(value){}
	virtual bool eval(const Arguments *args){
		if (mId == "true") return true;
		if (mId == "false") return false;
		return args->isTrue(mId);
	}
};

class LogicalAnd : public BooleanExpression{
	shared_ptr<BooleanExpression> mExp1,mExp2;
public:
	LogicalAnd(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2): mExp1(exp1), mExp2(exp2){
		log({"Creating LogicalAnd"});
	}
	virtual bool eval(const Arguments *args){
		if (logEval) log({"eval && : ", ptr()});
		bool e1=mExp1->eval(args);
		if (logEval) log({"eval && : ", ptr(), "left exp =", tf(e1)});
		bool res=e1 && mExp2->eval(args);
		if (logEval) log({"eval && : ", ptr(), tf(res)});
		return res;
	}
};


class LogicalOr : public BooleanExpression{
public:
	LogicalOr(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2): mExp1(exp1), mExp2(exp2){
		log({"Creating LogicalOr"});
	}
	virtual bool eval(const Arguments *args){
		if (logEval) log({"eval || : ", ptr()});
		bool e1=mExp1->eval(args);
		if (logEval) log({"eval || : ", ptr(), "left exp =", tf(e1)});

		bool res=e1 || mExp2->eval(args);
		if (logEval) log({"eval || : ", tf(res)});
		return res;
	}
private:
	shared_ptr<BooleanExpression> mExp1,mExp2;
};

class LogicalNot : public BooleanExpression{
public:
	LogicalNot(shared_ptr<BooleanExpression> exp) :mExp(exp){
		log({"Creating LogicalNot"});
	}
	virtual bool eval(const Arguments *args){
		bool res=!mExp->eval(args);
		if (logEval) log({"evaluating logicalnot : ", res?"true":"false"});
		return res;
	}
private:
	shared_ptr<BooleanExpression> mExp;
};


class EqualsOp : public BooleanExpression{
public:
	EqualsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2){
		log({"Creating EqualsOperator"});
	};
	virtual bool eval(const Arguments *args){
		bool res=mVar1->get(args)==mVar2->get(args);
		if (logEval) log({"evaluating ", mVar1->get(args), " == ", mVar2->get(args), " : ", res?"true":"false"});
		return res;
	}
private:
	shared_ptr<VariableOrConstant> mVar1,mVar2;
};


class UnEqualsOp : public BooleanExpression {
public:
	UnEqualsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2)
	: mVar1(var1), mVar2(var2){
		log({"Creating UnEqualsOperator"});
	};
	virtual bool eval(const Arguments *args){
		bool res=mVar1->get(args)!=mVar2->get(args);
		if (logEval) log({"evaluating ", mVar1->get(args), " != ", mVar2->get(args), " : ", res?"true":"false"});
		return res;
	}
private:
	shared_ptr<VariableOrConstant> mVar1,mVar2;
};


class NumericOp : public BooleanExpression{
	shared_ptr<VariableOrConstant> mVar;
public:
	NumericOp(shared_ptr<VariableOrConstant> var) : mVar(var){
		log({"Creating NumericOperator"});
	};
	virtual bool eval(const Arguments *args){
		string var=mVar->get(args);
		bool res=true;
		for (auto it=var.begin(); it != var.end(); ++it) {
			if (!isdigit(*it)) {
				res=false;
				break;
			}
		}
		if (logEval) log({"evaluating ", var, " is numeric : ", res?"true":"false"});
		return res;
	}
};


class DefinedOp : public BooleanExpression{
	shared_ptr<VariableOrConstant> mVar;
	string mName;
public:
	DefinedOp(string name, shared_ptr<VariableOrConstant> var) : mVar(var), mName(name){
		log({"Creating DefinedOperator"});
	};
	virtual bool eval(const Arguments *args){
		bool res=mVar->defined(args);
		if (logEval) log({"evaluating is defined for ", mName, res?"true":"false"});
		return res;
	}
};

class Regex : public BooleanExpression{
	shared_ptr<VariableOrConstant> mInput;
	shared_ptr<Constant> mPattern;
	regex_t preg;
	char error_msg_buff[100];
public:
	Regex(shared_ptr<VariableOrConstant> input, shared_ptr<Constant> pattern) : mInput(input),mPattern(pattern){
		log({"Creating Regular Expression"});
		string p= pattern->get(NULL);
		int err = regcomp(&preg,p.c_str(), REG_NOSUB | REG_EXTENDED);
		if (err !=0) throw new invalid_argument("couldn't compile regex " + p);
	};
	~Regex() {
		regfree(&preg);
	}
	virtual bool eval(const Arguments *args){
		string input=mInput->get(args);
		int match = regexec(&preg, input.c_str(), 0, NULL, 0);
		bool res;
		switch (match) {
		case 0:
			res=true;
			break;
		case REG_NOMATCH:
			res=false;
			break;
		default:
			regerror (match, &preg, error_msg_buff, sizeof(error_msg_buff));
			throw new invalid_argument("Error evaluating regex " + string(error_msg_buff));
			break;
		}

		if (logEval) log({"evaluating ", input, " is regex  " , mPattern->get(NULL), " : ", res?"true":"false"});
		return res;
	}
};

class ContainsOp : public BooleanExpression{
	shared_ptr<VariableOrConstant> mVar1,mVar2;
public:
	ContainsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2){};
	virtual bool eval(const Arguments *args){
		bool res=mVar1->get(args).find(mVar2->get(args))!=std::string::npos;
		if (logEval) log({"evaluating ", mVar1->get(args), " contains ", mVar2->get(args), " : ", res?"true":"false"});
		return res;
	}
};


class InOp : public BooleanExpression{
public:
	InOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2){};
	virtual bool eval(const Arguments *args){
		bool res=false;
		const list<string> &values=mVar2->getAsList(args);
		const string &varValue=mVar1->get(args);

		if (logEval) log({"Evaluating '", varValue, "' IN {", mVar2->get(args), "}"});
		for (auto it=values.begin(); it != values.end(); ++it) {
			if (logEval) log({"Trying '",  *it, "'"});
			if (varValue == *it) {
				res=true;
				break;
			}
		}
		if (logEval) log({"->", res?"true":"false"});
		return res;
	}
private:
	shared_ptr<VariableOrConstant> mVar1,mVar2;
};

static size_t find_first_non_word(const string &expr, size_t offset) {
	size_t i;
	for(i=offset;i<expr.size();++i){
		char c=expr[i];
		if (c != '-' && c != '.' && !isalnum(c)) return i;
	}
	return i;
}


shared_ptr<Variable> buildVariable(const string & expr, size_t *newpos){
	log({"buildVariable working on XX", expr, "XX"});
	while (expr[*newpos]==' ') *newpos+=1;

	size_t eow=find_first_non_word(expr, *newpos);
	if (eow <= *newpos && expr.size() > eow) {
		throw new invalid_argument("no variable recognized in X" + expr.substr(*newpos,string::npos)+"XX");
	}
	size_t len=eow-*newpos;
	auto var=expr.substr(*newpos, len);
	*newpos+=len;
	return make_shared<Variable>(var);
}

shared_ptr<Constant> buildConstant(const string & expr, size_t *newpos){
	log({"buildConstant working on XX", expr, "XX"});
	while (expr[*newpos]==' ') *newpos+=1;

	if (expr[*newpos]!='\'')
		throw new invalid_argument("Missing quote at start of " + expr);

	size_t end=expr.find_first_of('\'',*newpos+1);
	if (end!=string::npos){
		size_t len=end-*newpos-1;
		auto cons=expr.substr(*newpos+1,len);
		*newpos+=len +2; // remove the two '
		return make_shared<Constant>(cons);
	}else {
		throw new invalid_argument("Missing quote around " + expr);
	}
}

shared_ptr<VariableOrConstant> buildVariableOrConstant(const string & expr, size_t *newpos){
	log({"buildVariableOrConstant working on XX", expr, "XX"});
	while (expr[*newpos]==' ') *newpos+=1;

	if (expr[*newpos]=='\''){
		auto constant=buildConstant(expr, newpos);
		return dynamic_pointer_cast<VariableOrConstant>(constant);
	}else{
		auto variable=buildVariable(expr, newpos);
		return dynamic_pointer_cast<VariableOrConstant>(variable);

	}
	throw new invalid_argument("Couldn't find variable or constant in " + expr);
}

static size_t find_matching_closing_parenthesis(const string &expr, size_t offset){
	size_t i;
	int match=1;
	for(i=offset;i<expr.size();++i){
		if (expr[i]=='(') ++match;
		else if (expr[i]==')') --match;
		if (match==0) return i;
	}
	return string::npos;
} 

bool isKeyword(const string &expr, size_t *newpos, const string &keyword) {
	size_t pos=*newpos;
	size_t keyLen=keyword.size();
	size_t availableLen=expr.size()-pos;
	if (availableLen < keyLen) return false;

	for (size_t i = 0; i < keyLen; ++i) {
		if (expr[pos+i] != keyword[i]) return false;
	}

	if (availableLen > keyLen && isalnum(expr[pos+keyLen])) return false;

	*newpos+=keyLen;
	log({"Recognized keyword '", keyword, "'"});
	return true;
}

static void printState(const string &str, size_t pos) {
	log({"Working on " , str});
	ostringstream oss;
	for (size_t i=0; i < pos + 11; ++i) oss << " ";
	oss << "^";
	if (pos < str.size()) {
		oss << str.substr(pos, 1);
	}
	log({oss.str()});
}

shared_ptr<BooleanExpression> parseExpression(const string & expr, size_t *newpos){
	size_t i;

	log({"Parsing expression ", expr});
	shared_ptr<BooleanExpression> cur_exp;
	shared_ptr<VariableOrConstant> cur_var;

	for (i=0;i<expr.size();){
		size_t j=0;
		printState(expr, *newpos+i);
		switch(expr[i]){
		case '(':
		{
			size_t end=find_matching_closing_parenthesis(expr,i+1);
			if (end!=string::npos){
				cur_exp=parseExpression(expr.substr(i+1,end-i-1),&j);
				i=end+1;
			}else {
				throw new invalid_argument("Missing parenthesis around " + expr);
			}
		}
		break;
		case '&':
			if (expr[i+1]=='&'){
				if (!cur_exp){
					throw new logic_error("&& operator expects first operand.");
				}
				i+=2;
				cur_exp=make_shared<LogicalAnd>(cur_exp,parseExpression(expr.substr(i),&j));
				i+=j;
			}else{
				throw new logic_error("Bad operator '&'");
			}
			break;
		case '|':
			if (expr[i+1]=='|'){
				if (!cur_exp){
					throw new logic_error("|| operator expects first operand.");
				}
				i+=2;
				cur_exp=make_shared<LogicalOr>(cur_exp,parseExpression(expr.substr(i),&j));
				i+=j;
			}else{
				throw new invalid_argument("Bad operator '|'");
			}
			break;
		case '!':
			if (expr[i+1]=='='){
				if (!cur_var){
					throw new invalid_argument("!= operator expects first variable or const operand.");
				}
				i+=2;
				cur_exp=make_shared<UnEqualsOp>(cur_var,buildVariableOrConstant(expr.substr(i),&j));
			}
			else {
				if (cur_exp){
					throw new invalid_argument("Parsing error around '!'");
				}
				i++;
				for (;expr[i]==' ';++i); //skip spaces (we are fair)

				if (isKeyword(expr.substr(i), &(j=0), "true")) {
					i+=j; j=0;
					cur_exp=make_shared<TrueFalseExpression>("true");
				} else if (isKeyword(expr.substr(i), &(j=0), "false")) {
					i+=j; j=0;
					cur_exp=make_shared<TrueFalseExpression>("false");
				} else if (isKeyword(expr.substr(i), &(j=0), "numeric")) {
					i+=j; j=0;
					auto var=buildVariableOrConstant(expr.substr(i),&j);
					cur_exp=make_shared<NumericOp>(var);
				} else if (expr[i]=='(') {
					size_t end=find_matching_closing_parenthesis(expr,i+1);
					if (end!=string::npos){
						cur_exp=parseExpression(expr.substr((i+1),end-(i+1)),&j);
						i=end+1;
						j=0; // no use
					}else {
						throw new invalid_argument("Missing parenthesis around " + expr);
					}
				} else {
					ostringstream oss; oss << expr[i];
					log({">", oss.str(), ""});
					throw new invalid_argument("! operator expects boolean value or () expression.");

				}

				// Take the negation!
				cur_exp=make_shared<LogicalNot>(cur_exp);

			}
			i+=j;
			break;
		case '=':
			if (expr[i+1]=='='){
				if (!cur_var){
					throw new invalid_argument("== operator expects first variable or const operand.");
				}
				i+=2;
				cur_exp=make_shared<EqualsOp>(cur_var,buildVariableOrConstant(expr.substr(i),&j));
				i+=j;
			}else{
				throw new invalid_argument("Bad operator =");
			}
			break;
		case ' ':
			log({"skipping space"});
			i++;
			break;
		case 'c':
			if (isKeyword(expr.substr(i), &j, "contains")) {
				i+=j;
				j=0;
				auto rightVar= buildVariableOrConstant(expr.substr(i),&j);
				cur_exp=make_shared<ContainsOp>(cur_var, rightVar);
				i+=j;
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		case 'd':
			if (isKeyword(expr.substr(i), &j, "defined")) {
				i+=j;
				j=0;
				auto rightVar= buildVariableOrConstant(expr.substr(i),&j);
				cur_exp=make_shared<DefinedOp>(expr.substr(i, j), rightVar);
				i+=j;
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		case 'r':
			if (isKeyword(expr.substr(i), &j, "regex")) {
				i+=j;
				j=0;
				auto pattern= buildConstant(expr.substr(i),&j);
				cur_exp=make_shared<Regex>(cur_var, pattern);
				i+=j;
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		case 'i':
			if (isKeyword(expr.substr(i), &j, "in")) {
				i+=j; j=0;
				auto rightVar= buildVariableOrConstant(expr.substr(i),&j);
				cur_exp=make_shared<InOp>(cur_var, rightVar);
				i+=j;
			} else if (isKeyword(expr.substr(i), &j, "is_request")) {
				i+=j; j=0;
				cur_exp=make_shared<TrueFalseExpression>("is_request");
			} else if (isKeyword(expr.substr(i), &j, "is_response")) {
				i+=j; j=0;
				cur_exp=make_shared<TrueFalseExpression>("is_response");
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		case 't':
			if (isKeyword(expr.substr(i), &j, "true")) {
				i+=j; j=0;
				cur_exp=make_shared<TrueFalseExpression>("true");
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		case 'f':
			if (isKeyword(expr.substr(i), &j, "false")) {
				i+=j; j=0;
				cur_exp=make_shared<TrueFalseExpression>("false");
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		case 'n':
			if (isKeyword(expr.substr(i), &j, "numeric")) {
				if (cur_exp || cur_var){
					throw new invalid_argument("Parsing error around 'numeric'");
				}
				i+=j; j=0;
				auto var=buildVariableOrConstant(expr.substr(i),&j);
				cur_exp=make_shared<NumericOp>(var);
				i+=j; j=0;
				// fixme should check all is finished now
			} else if (isKeyword(expr.substr(i), &j, "nin") || isKeyword(expr.substr(i), &j, "notin")) {
				i+=j; j=0;
				auto rightVar= buildVariableOrConstant(expr.substr(i),&j);
				auto in=make_shared<InOp>(cur_var, rightVar);
				cur_exp=make_shared<LogicalNot>(in);
				i+=j;
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&j);
				i+=j;j=0;
			}
			break;
		default:
			cur_var=buildVariableOrConstant(expr.substr(i),&j);
			i+=j;j=0;
			break;
		}
	}
	*newpos+=i;
	return cur_exp;
};



