
#include "../recordserializer.hh"
#include "../log/logmanager.hh"
#include <memory>
#include <map>
#include <iostream>
#include <cstring>



using namespace std;
#define BAD(reason) do {cout << reason << endl ; exit(-1);} while (0)

bool sUseSyslog;

static void init() {
	sUseSyslog=false;
	flexisip::log::preinit(sUseSyslog, flexisip::log::debug);
	flexisip::log::initLogs(sUseSyslog, flexisip::log::debug);
	flexisip::log::updateFilter("%Severity% >= debug");
	
	Record::sLineFieldNames = {"line"};
	Record::sMaxContacts = 10;
}

static ExtendedContact &firstContact(const Record &r) {
	return *r.getExtendedContacts().cbegin()->get();
}

ostream &operator<<(ostream &stream, const list<string> &str) {
	for (auto it=str.cbegin(); it != str.cend(); ++it) {
		if (it != str.cbegin()) stream << ",";
		stream << *it;
	}
	return stream;
}

template<typename CompT>
inline void check(const string &name, const CompT &v1, const CompT &v2) {
	if (v1 != v2) BAD(name << " " << v1 << " / " << v2);
}

static bool compare(const ExtendedContact &ec1, bool alias,
		    const ExtendedContactCommon &common, uint32_t cseq, time_t expireat,float q, const string &sipuri, time_t updatedTime) {
	check("alias", ec1.mAlias, alias);
	check("callid", ec1.mCallId, common.mCallId);
	check("contactid", ec1.mContactId, common.mContactId);
	check("line", ec1.mLineValueCopy, common.mLineValueCopy);
	check("path", ec1.mPath, common.mPath);
	check("cseq", ec1.mCSeq, cseq);
	check("mExpireAt", ec1.mExpireAt, expireat);
	check("mQ", ec1.mQ, q);
	check("mSipUri", ec1.mSipUri, sipuri);
	check("mUpdatedTime", ec1.mUpdatedTime, updatedTime);
	
	return true;
}

static bool compare(const ExtendedContact &ec1, const ExtendedContact &ec2) {
	ExtendedContactCommon ecc(ec2.mContactId.c_str(), ec2.mPath, ec2.mCallId.c_str(), ec2.mLineValueCopy.c_str());
	return compare(ec1, ec2.mAlias, ecc,
		       ec2.mCSeq, ec2.mExpireAt, ec2.mQ, ec2.mSipUri, ec2.mUpdatedTime);
}

static bool compare(const Record &r1, const Record &r2) {
	auto ec1 = r1.getExtendedContacts();
	auto ec2 = r2.getExtendedContacts();
	if (ec1.size() != ec2.size()) BAD("ecc size :" << ec1.size() << " / " << ec2.size());

	return compare(firstContact(r1), firstContact(r2));
}
int main(int argc, char **argv) {
	if (argc != 2) { cerr << "bad usage" << endl; exit(-1); }
	init();
	auto serializer = unique_ptr<RecordSerializer>(RecordSerializer::create(argv[1]));
	if (!serializer) { cerr << "bad serializer" << argv[1] << endl; exit(-1); }

	Record initial("key");
	list<string> paths{"path1", "path2", "path3"};
	string contactid {"contactid"};
	string callid {"callid"};
	string line {"line"};
	string contact {"guillaume@bc"};
	uint32_t cseq=123456;
	time_t now=time(NULL);
	time_t expireat=now + 1000;
	float quality=1;


	ExtendedContactCommon ecc(contactid.c_str(),paths, callid.c_str(), line.c_str());
	initial.bind(ecc, contact.c_str(), expireat, quality, cseq, now, false);
	if (!compare(firstContact(initial), false, ecc, cseq, expireat, quality, contact, now)) {
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
	return 0;
}
