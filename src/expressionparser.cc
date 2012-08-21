
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

#ifndef TEST_BOOL_EXPR
#include "common.hh"
#endif


using namespace::std;


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
	unsigned long pos=0;
	auto expr = parseExpression(str, &pos);
	return expr;
}

static bool logEval=true;
static void log(initializer_list<string> tuple) {
#ifdef TEST_BOOL_EXPR
	for (string str : tuple) cout << str;
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
		log({"Creating constant ", val});
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
		log({"Creating variable ", val});
	}
	virtual const std::string &get(const Arguments *args) {
		mVal=args->get(mId);
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
public:
	LogicalAnd(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2): mExp1(exp1), mExp2(exp2){
		log({"Creating LogicalAnd"});
	}
	virtual bool eval(const Arguments *args){
		return mExp1->eval(args) && mExp2->eval(args);
	}
private:
	shared_ptr<BooleanExpression> mExp1,mExp2;
};


class LogicalOr : public BooleanExpression{
public:
	LogicalOr(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2): mExp1(exp1), mExp2(exp2){
		log({"Creating LogicalOr"});
	}
	virtual bool eval(const Arguments *args){
		return mExp1->eval(args) || mExp2->eval(args);
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
		return !mExp->eval(args);
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
		if (logEval) log({"evaluating ", mVar1->get(args), " == ", mVar2->get(args)});
		return mVar1->get(args)==mVar2->get(args);
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
		if (logEval) log({"evaluating ", mVar1->get(args), " != ", mVar2->get(args)});
		return mVar1->get(args)!=mVar2->get(args);
	}
private:
	shared_ptr<VariableOrConstant> mVar1,mVar2;
};

class ContainsOp : public BooleanExpression{
public:
	ContainsOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2){};
	virtual bool eval(const Arguments *args){
		return mVar1->get(args).find(mVar2->get(args))!=std::string::npos;
	}
private:
	shared_ptr<VariableOrConstant> mVar1,mVar2;
};


class InOp : public BooleanExpression{
public:
	InOp(shared_ptr<VariableOrConstant> var1, shared_ptr<VariableOrConstant> var2) : mVar1(var1), mVar2(var2){};
	virtual bool eval(const Arguments *args){
		const list<string> &values=mVar2->getAsList(args);
		const string &varValue=mVar1->get(args);

		if (logEval) log({"Evaluating '", varValue, "' IN {", mVar2->get(args), "}"});
		for (auto it=values.begin(); it != values.end(); ++it) {
			if (logEval) log({"Trying '",  *it, "'"});
			if (varValue == *it) return true;
		}
		return false;
	}
private:
	shared_ptr<VariableOrConstant> mVar1,mVar2;
};

static size_t find_first_non_word(const string &expr, size_t offset) {
	size_t i;
	for(i=offset;i<expr.size();++i){
		char c=expr[i];
		if (!isalnum(c)) return i;
	}
	return i;
}

shared_ptr<VariableOrConstant> buildVariableOrConstant(const string & expr, size_t *newpos){
	log({"buildVariableOrConstant working on ", expr});
	int i;
	for (i=0;expr[i]==' ';++i);
	if (expr[i]=='\''){
		size_t end=expr.find_first_of('\'',i+1);
		if (end!=string::npos){
			*newpos+=end+1;
			auto constant=make_shared<Constant>(expr.substr(i+1,end-i-1));
			return dynamic_pointer_cast<VariableOrConstant>(constant);
		}else {
			throw new invalid_argument("Missing quote around " + expr);
		}
	}else{
		size_t eow=find_first_non_word(expr, *newpos);
		if (eow <= *newpos) {
			throw new invalid_argument("Unrecognized variable " + expr.substr(i,string::npos));
		}
		*newpos=eow;
		auto identifier=expr.substr(i, eow);
		auto variable=make_shared<Variable>(identifier);
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
				cur_exp=make_shared<LogicalNot>(parseExpression(expr.substr(i),&j));
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
				cur_var=buildVariableOrConstant(expr.substr(i),&i);
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
				cur_var=buildVariableOrConstant(expr.substr(i),&i);
			}
			break;
		case 't':
			if (isKeyword(expr.substr(i), &j, "true")) {
				i+=j; j=0;
				cur_exp=make_shared<TrueFalseExpression>("true");
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&i);
			}
			break;
		case 'f':
			if (isKeyword(expr.substr(i), &j, "false")) {
				i+=j; j=0;
				cur_exp=make_shared<TrueFalseExpression>("false");
			} else {
				cur_var=buildVariableOrConstant(expr.substr(i),&i);
			}
			break;
		default:
			cur_var=buildVariableOrConstant(expr.substr(i),&i);
			break;
		}
	}
	*newpos+=i;
	return cur_exp;
};


class FakeArguments : public Arguments {
	map<string,string> mStringArgs;
	map<string,bool> mBoolArgs;

	void insertArg(char *keyval) {
		cout << "Parsing keyval arg " << keyval << endl;
		int i=0;
		while(true) {
			if (!keyval[i]) {
				throw new invalid_argument("No character '=' in the string " + string(keyval));
			} else if (keyval[i] == '=') {
				keyval[i]=0;
				char firstValueChar=keyval[i+1];
				if (firstValueChar == '0') {
					mBoolArgs.insert(make_pair(keyval, false));
				} else if (firstValueChar == '1') {
					mBoolArgs.insert(make_pair(keyval, true));
				} else {
					mStringArgs.insert(make_pair(keyval, keyval+i+1));
				}
				return;
			}
			++i;
		}
	}
public:
	FakeArguments(const char *s) {
		char *dup=strdup(s);
		char *p = strtok(dup, "|");
		while (p) {
			insertArg(p);
		    p = strtok(NULL, "|");
		}
		free(dup);
	}

	virtual string get(const std::string &id) const {
		auto it=mStringArgs.find(id);
		if (it != mStringArgs.end()) return (*it).second;
		throw new runtime_error("unknown argument " + id);
	}

	virtual bool isTrue(const string &id) const {
		auto it=mBoolArgs.find(id);
		if (it != mBoolArgs.end()) return (*it).second;
		throw new runtime_error("unknown argument " + id);
	}
};

#ifdef TEST_BOOL_EXPR

int main(int argc, char *argv[]){
	if (argc != 3 || argv[1] == "-h" || argv[1] =="--help") {
		cout << argv[0] << " \"bool expr\" \"key1=val1|key2=val2|key3=0|key4=1\"" <<endl;
		return 0;
	}

	try {
		shared_ptr<BooleanExpression> expr=BooleanExpression::parse(argv[1]);
		if (expr){
			FakeArguments args(argv[2]);
			cout<<"Result: " << (expr->eval(&args) ? "true" : "false" )<< endl;
		}
	} catch(invalid_argument *e){
		std::cerr << "Invalid argument " << e->what() << std::endl;
		throw;
	}

	return 0;
}

#endif


