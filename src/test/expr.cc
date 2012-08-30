#include "../expressionparser.hh"
#include <memory>
#include <map>
#include <stdexcept>
#include <iostream>
#include <cstring>


using namespace std;

static size_t count=0;
static bool error_occured=false;


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
				char next=keyval[i+2];
				if (firstValueChar == '0' && !next) {
					cout << "Inserting bool " << keyval << "->" << "false" <<endl;
					mBoolArgs.insert(make_pair(keyval, false));
				} else if (firstValueChar == '1' && !next) {
					cout << "Inserting bool " << keyval << "->" << "true" <<endl;
					mBoolArgs.insert(make_pair(keyval, true));
				} else {
					cout << "Inserting string " << keyval << "->" << keyval+i+1 <<endl;
					mStringArgs.insert(make_pair(keyval, keyval+i+1));
				}
				return;
			}
			++i;
		}
	}
public:
	FakeArguments(const char *s) {
		const char *sep = "|";
		char *dup=strdup(s);
		char *p = strtok(dup, sep);
		while (p) {
			insertArg(p);
			p = strtok(NULL, sep);
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


static void print_test_value(size_t nb, const char *expr, const char* args, bool expected, bool actual) {
	bool success=expected == actual;
	string res=success ? "[OK]" : "[KO]";
	cerr << res << " " << (int)nb;
	if (!success) {
		cerr << " expected " << (expected ? string("true"):string("false")); 
		cerr << " = " << string(expr) << endl << "[" << string(args) << "]";
		error_occured=true;
	}
	cerr << endl;

}

static void btest(bool expected, const char *expr, const char *argstr) {
	++count;
	bool success=false;
	try {
		string s(expr);
		shared_ptr<BooleanExpression> be=BooleanExpression::parse(s);
		if (be){
			FakeArguments args(argstr);
			bool res=success=be->eval(&args);
			print_test_value(count, expr, argstr, expected, res);
		}
	} catch(exception *e){
		std::cerr << "[KO] " << count << " exception " << e->what() << std::endl;
	}
}


static void btest_true(const char *expr, const char *argstr) {
	btest(true, expr, argstr);
}

static void btest_false(const char *expr, const char *argstr) {
	btest(false, expr, argstr);
}

void do_interceptor_tests() {
	count=0; cerr << "Suite interceptor" << endl;
	const char *expr="is_response || !(ua contains 'Linphone/3.5.2') || ((request.method-name == 'INVITE') && !(request.uri.user contains 'ip'))";

	btest_true(expr, "is_response=0|ua=Linphone/3.5.2|request.method-name=INVITE|request.uri.user=45645");
	btest_false(expr, "is_response=0|ua=Linphone/3.5.2|request.method-name=INVITE|request.uri.user=45645ip");

}

void do_true_false(void) {
	count=0; cerr << "Suite bool" << endl;
	btest_true("true","");
	btest_false("false","");
}

void do_or(void) {
	count=0; cerr << "Suite or" << endl;
	btest_false("false||false","");
	btest_false("false||false||false","");
	btest_true("false||false||true","");
}

void do_and(void) {
	count=0; cerr << "Suite and" << endl;
	btest_true("true&&true","");
	btest_true("true&&true&&true","");
	btest_false("false&&true","");
	btest_false("true&&false","");
	btest_false("true&&true&&false","");
}


void do_const(void) {
	count=0; cerr << "Suite const" << endl;
	btest_false("'a'=='b'","");
	btest_true("'a'=='a'","");
}


void do_var(void) {
	count=0; cerr << "Suite var" << endl;
	btest_true("a==''","a=");
	btest_true("a=='test'","a=test");
	btest_false("a=='test'","a=different");
}

void do_regex(void) {
	count=0; cerr << "Suite regex" << endl;
	btest_true("a regex 'toto'","a=toto");
	btest_false("a regex 'toto'","a=titi");
}

void do_numeric(void) {
	count=0; cerr << "Suite numeric" << endl;
	btest_true("numeric aa","aa=12345");
	btest_false("numeric a","a=123ip");
}

void do_predefined_tests(void) {
	do_true_false();
	do_or();
	do_and();
	do_const();
	do_var();

	btest_true("false||(a=='toto')||false","a=toto");
	btest_false("false||(a=='toto')||false","a=titi");
	btest_true("!(true) || true", "");

	do_numeric();
	do_regex();

	do_interceptor_tests();
}

void do_cmd_test(int argc, char *argv[]) {
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
}

int main(int argc, char *argv[]){
	log_boolean_expression_evaluation(true);
	log_boolean_expression_parsing(true);
	if (argc == 1) {
		do_predefined_tests();
		return error_occured;
	} 

	if (argc != 3 || string(argv[1]) == "-h" || string(argv[1]) =="--help") {
		cout << argv[0] << " \"bool expr\" \"key1=val1|key2=val2|key3=0|key4=1\"" <<endl;
		return -1;
	}

	do_cmd_test(argc, argv);
	return error_occured;
}

