
#include "test_utils.hh"
#include <src/registrardb-internal.hh>
#include "../registrardb.hh"

using namespace std;
bool sUseSyslog;


struct MyListener : public RegistrarDbListener {
	RegistrarDb::BindParameters params;
	MyListener(const RegistrarDb::BindParameters &params): params(params) {};
	virtual void onRecordFound(Record *r) {
// 		cout << "record found : ";
// 		r->print(cout);
// 		cout << endl;
		auto ecc=firstContact(*r);
		long rExpire=ecc.mExpireAt-ecc.mUpdatedTime;
		check("expire",atol(params.sip.contact->m_expires), rExpire);
	}
	virtual void onError() {
		BAD("RegistrarDbListener:error");
	}
	virtual void onInvalid() {
		BAD("RegistrarDbListener:invalid");
	}
};

SofiaHome home;


void checkExpireHandling() {
	check("resolve expire1", ExtendedContact::resolve_expire(NULL, 5), 5);
	check("resolve expire2", ExtendedContact::resolve_expire(NULL, -1), -1);
	check("resolve expire3", ExtendedContact::resolve_expire("5", 6), 5);
	check("resolve expire4", ExtendedContact::resolve_expire("5", -1), 5);
}

static sip_contact_t *uid_ct(const char *urlparams, const char* ctparams) {
	return sip_contact_format(
		home.h, "<%s%s>%s", "sip:localhost:12345",
		urlparams,
		ctparams);
}
void checkUniqueIdExtraction() {
	#define UID_PARAM theparam
	string theparam = "UID_PARAM";
	check("+sip.instance in ct param",
		Record::extractUniqueId(uid_ct("", ";+sip.instance=UID_PARAM"))
		, theparam);

	check("+sip.instance in url param",
		Record::extractUniqueId(uid_ct(";+sip.instance=UID_PARAM", ""))
		, theparam);

	check("line in ct param",
		Record::extractUniqueId(uid_ct("", ";line=UID_PARAM"))
		, theparam);

	check("line url param",
		Record::extractUniqueId(uid_ct(";line=UID_PARAM", ""))
		, theparam);
}
int main(int argc, char **argv) {
	init_tests();

	checkExpireHandling();
	checkUniqueIdExtraction();

	int expire_delta= 1000;
	list<string> paths{"path1", "path2", "path3"};
	string contactid {"ip:5223"};
	string callid {"callid"};
	string line {"line"};
	string contact = "sip:" + contactid + ";line="+line;
	string contactWithChev = "<" + contact + ">";
	uint32_t cseq=123456;
	float quality=1;
	bool alias=false;
	const url_t *from=url_make(home.h, "sip:guillaume@bc");

	ExtendedContactCommon ecc(contactid.c_str(),paths, callid.c_str(), line.c_str());

	sip_contact_t *sip_contact= sip_contact_format(home.h, "<%s>;q=%f;expires=%d",
			contact.c_str(), quality, expire_delta);
	sip_path_t *sip_path=path_fromstl(home.h ,paths);

	
	RegistrarDbInternal registrar("preferred_ip");
	RegistrarDb::BindParameters params(
		RegistrarDb::BindParameters::SipParams(
			from, sip_contact, callid.c_str(), cseq, sip_path
		), 55555, alias
	);
	auto listener=make_shared<MyListener>(params);
	registrar.bind(params, listener);

	registrar.clearAll();
	cout << "success" << endl;
	return 0;
}

