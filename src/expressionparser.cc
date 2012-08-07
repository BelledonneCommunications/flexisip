
#include <memory>
#include <string>
#include <iostream>

using namespace::std;

class Arguments{
	public:
		//sip_t *mSip;
		int toto;
};

class Variable{
	public:
		virtual std::string get(const Arguments &args)=0;
};

class Constant : public Variable{
	public:
		Constant(const std::string &val): mVal(val){
			cout<<"Creating constant "<<val<<endl;		
		};
		virtual std::string get(const Arguments &args){
			return mVal;		
		}
	private:
		const std::string mVal;
};


class BooleanExpression{
	public:
		virtual bool eval(const Arguments &args)=0;
};



class LogicalAnd : public BooleanExpression{
	public:
		LogicalAnd(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2): mExp1(exp1), mExp2(exp2){
			cout<<"Creating LogicalAnd"<<endl;
		}
		virtual bool eval(const Arguments & args){
			return mExp1->eval(args) && mExp2->eval(args);
		}
	private:
		shared_ptr<BooleanExpression> mExp1,mExp2;
};


class LogicalOr : public BooleanExpression{
	public:
		LogicalOr(shared_ptr<BooleanExpression> exp1, shared_ptr<BooleanExpression> exp2): mExp1(exp1), mExp2(exp2){
			cout<<"Creating LogicalOr"<<endl;
		}
		virtual bool eval(const Arguments & args){
			return mExp1->eval(args) || mExp2->eval(args);
		}
	private:
		shared_ptr<BooleanExpression> mExp1,mExp2;
};

class LogicalNot : public BooleanExpression{
	public:
		LogicalNot(shared_ptr<BooleanExpression> exp) :mExp(exp){
			cout<<"Creating LogicalNot"<<endl;
		}
		virtual bool eval(const Arguments &args){
			return !mExp->eval(args);
		}
	private:
		shared_ptr<BooleanExpression> mExp;
};

class EqualsOperator : public BooleanExpression{
	public:
		EqualsOperator(shared_ptr<Variable> var1, shared_ptr<Variable> var2) : mVar1(var1), mVar2(var2){
			cout<<"Creating EqualsOperator"<<endl;		
		};
		virtual bool eval(const Arguments & args){
			return mVar1->get(args)==mVar2->get(args);
		}
	private:
		shared_ptr<Variable> mVar1,mVar2;
};

class ContainsOperator : public BooleanExpression{
	public:
		ContainsOperator(shared_ptr<Variable> var1, shared_ptr<Variable> var2) : mVar1(var1), mVar2(var2){};
		virtual bool eval(const Arguments & args){
			return mVar1->get(args).find(mVar2->get(args))!=std::string::npos;
		}
	private:
		shared_ptr<Variable> mVar1,mVar2;
};

shared_ptr<Variable> buildVariable(const string & expr, size_t *newpos){
	int i;
	for (i=0;expr[i]==' ';++i);
	if (expr[i]=='\''){
		size_t end=expr.find_first_of('\'',i+1);
		if (end!=string::npos){
			*newpos+=end+1;
			return make_shared<Constant>(expr.substr(i+1,end-i-1));
		}else {
			cout<<"Missing quote around "<<expr<<endl;
			return NULL;
		}
	}else{
		cout<<"Unrecognized variable "<<expr.substr(i,string::npos)<<endl;
	}
	return NULL;
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

shared_ptr<BooleanExpression> buildExpression(const string & expr, size_t *newpos){
	size_t i;

	cout << "Parsing expression " << expr<<endl;
	shared_ptr<BooleanExpression> cur_exp;
	shared_ptr<Variable> cur_var;

	for (i=0;i<expr.size();){
		switch(expr[i]){
			case '(':
				{
					size_t end=find_matching_closing_parenthesis(expr,i+1);
					if (end!=string::npos){
						cur_exp=buildExpression(expr.substr(i+1,end-i-1),&i);
						i=end+1;
						if (cur_exp==NULL) return NULL;
					}else {
						cout<<"Missing parenthesis around "<<expr<<endl;
						return NULL;
					}
				}
			break;
			case '&':
				if (expr[i+1]=='&'){
					if (cur_exp==NULL){
						cout<<"&& operator expects first operand."<<endl;
						return NULL;
					}
					i+=2;
					cur_exp=make_shared<LogicalAnd>(cur_exp,buildExpression(expr.substr(i,string::npos),&i));
				}else{
					cout << "Bad operator '&'"<<endl;
					return NULL;
				}
			break;
			case '|':
				if (expr[i+1]=='|'){
					if (cur_exp==NULL){
						cout<<"|| operator expects first operand."<<endl;
						return NULL;
					}
					i+=2;
					cur_exp=make_shared<LogicalOr>(cur_exp,buildExpression(expr.substr(i,string::npos),&i));
				}else{
					cout << "Bad operator '|'"<<endl;
					return NULL;
				}
			break;
			case '!':
				i++;
				if (cur_exp){
					cout<<"Parsing error around '!'"<<endl;
					return NULL;
				}
				cur_exp=make_shared<LogicalNot>(buildExpression(expr.substr(i,string::npos),&i));
				if (cur_exp==NULL) return NULL;
			break;
			case '=':
				if (expr[i+1]=='='){
					if (cur_var==NULL){
						cout<<"== operator expects first variable or const operand."<<endl;
						return NULL;
					}
					i+=2;
					cur_exp=make_shared<EqualsOperator>(cur_var,buildVariable(expr.substr(i,string::npos),&i));
				}else{
					cout << "Bad operator ="<<endl;
					return NULL;
				}
			break;
			case ' ':
				i++;
			break;
			default:
				cur_var=buildVariable(expr.substr(i,string::npos),&i);
				if (cur_var==NULL) return NULL;
			break;
		}
	}
	*newpos+=i;
	return cur_exp;
};

int main(int argc, char *argv[]){
	size_t pos=0;
	shared_ptr<BooleanExpression> expr=buildExpression(argv[1],&pos);
	if (expr){
		Arguments args;
		cout<<"Result: " << ((expr->eval(args)) ? "true" : "false" )<< endl;
	}
	return 0;
}




