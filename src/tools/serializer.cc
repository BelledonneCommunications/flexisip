
#include "tool_utils.hh"

using namespace std;
bool sUseSyslog;

int test_bind_with_ecc(ExtendedContactCommon &ecc, const unique_ptr<RecordSerializer> &serializer, string contact, time_t expireat, float quality, long cseq, time_t now, bool alias, sip_accept_t *accept) {
	Record initial("key");
	
	list<string> acceptHeaders;
	while (accept != NULL) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}
	
	initial.update(ecc, contact.c_str(), expireat, quality, cseq, now, alias, acceptHeaders);
	if (!compare(firstContact(initial), alias, ecc, cseq, expireat, quality, contact, now)) {
		cerr << "Initial and parameters differ" << endl;
		return -1;
	}
	
	string serialized;
	if (!serializer->serialize(&initial, serialized, true)) {
		cerr << "Failed serializing" << endl;
		return -1;
	}
	
	Record final("key");
	if (!serializer->parse(serialized, &final)) {
		cerr << "Failed parsing" << endl;
		return -1;
	}
	
	if (!compare(initial, final)) {
		cerr << "Initial and final initial differs" << endl;
		return -1;
	}

	cerr << "success : test_bind_with_ecc" << endl;
	return 0;
}

int test_bind_without_ecc(ExtendedContactCommon &ecc, const unique_ptr<RecordSerializer> &serializer,
			  sip_contact_t *contacts, sip_path_t *path, int globalexpire, const char *callid,
			  string contact, time_t expireat, float quality, long cseq, time_t now, bool alias, sip_accept_t *accept) {
	Record initial("key");
	
	list<string> acceptHeaders;
	while (accept != NULL) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}
	
	initial.update(contacts, path, globalexpire, callid, cseq, now, alias, acceptHeaders);
	if (!compare(firstContact(initial), alias, ecc, cseq, expireat, quality, contact, now)) {
		cerr << "Initial and parameters differ" << endl;
		return -1;
	}
	
	string serialized;
	if (!serializer->serialize(&initial, serialized, true)) {
		cerr << "Failed serializing" << endl;
		return -1;
	}
	
	Record final("key");
	if (!serializer->parse(serialized, &final)) {
		cerr << "Failed parsing" << endl;
		return -1;
	}
	
	if (!compare(initial, final)) {
		cerr << "Initial and final initial differs" << endl;
		return -1;
	}

	cerr << "success : test_bind_without_ecc" << endl;
	return 0;
}

SofiaHome home;

int main(int argc, char **argv) {
	if (argc != 2) { cerr << "bad usage" << endl; exit(-1); }
	init_tests();
	auto serializer = unique_ptr<RecordSerializer>(RecordSerializer::create(argv[1]));
	if (!serializer) { cerr << "bad serializer" << argv[1] << endl; exit(-1); }

	int expire_delta= 1000;
	list<string> paths{"path1", "path2", "path3"};
	string contactid {"ip:5223"};
	string callid {"callid"};
	string line {"line"};
	string contact = "sip:" + contactid + ";line="+line;
	string contactWithChev = "<" + contact + ">";
	uint32_t cseq=123456;
	time_t now=time(NULL);
	time_t expireat=now + expire_delta;
	float quality=1;
	bool alias=false;

	ExtendedContactCommon ecc(contactid.c_str(),paths, callid.c_str(), line.c_str());

	sip_contact_t *sip_contact= sip_contact_format(home.h, "<%s>;q=%f;expires=%d",
			contact.c_str(), quality, expire_delta);
	sip_path_t *sip_path=path_fromstl(home.h ,paths);
	sip_accept_t *accept = NULL;

	if (test_bind_with_ecc(ecc, serializer, contact, expireat, quality, cseq, now, alias, accept)) {
		BAD("failure in bind with ecc");
	}
	
	if (test_bind_without_ecc(ecc, serializer, sip_contact, sip_path, 55555, callid.c_str(),
		contactWithChev.c_str(), expireat, quality, cseq, now, alias, accept)) {
		BAD("failure in bind without ecc");
	}

	cout << "success" << endl;
	return 0;
}
