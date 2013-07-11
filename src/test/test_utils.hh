
#ifndef _TEST_UTILS
#define _TEST_UTILS
#include "../recordserializer.hh"
#include "../log/logmanager.hh"
#include <memory>
#include <map>
#include <iostream>
#include <cstring>

#define BAD(reason) do {std::cout << reason << std::endl ; exit(-1);} while (0)


void init_tests() {
	sUseSyslog=false;
	flexisip::log::preinit(sUseSyslog, flexisip::log::debug);
	flexisip::log::initLogs(sUseSyslog, flexisip::log::debug);
	flexisip::log::updateFilter("%Severity% >= debug");
	
	Record::sLineFieldNames = {"+sip.instance", "pn-tok", "line"};
	Record::sMaxContacts = 10;
}

ExtendedContact &firstContact(const Record &r) {
	return *r.getExtendedContacts().cbegin()->get();
}

std::ostream &operator<<(std::ostream &stream, const std::list<std::string> &str) {
	for (auto it=str.cbegin(); it != str.cend(); ++it) {
		if (it != str.cbegin()) stream << ",";
		stream << *it;
	}
	return stream;
}

template<typename CompT>
inline void check(const std::string &name, const CompT &v1, const CompT &v2) {
	if (v1 != v2) BAD(name << " X" << v1 << "X / X" << v2 << "X");
}

bool compare(const ExtendedContact &ec1, bool alias,
	     const ExtendedContactCommon &common, uint32_t cseq, time_t expireat,float q, const std::string &sipuri, time_t updatedTime) {
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

bool compare(const ExtendedContact &ec1, const ExtendedContact &ec2) {
	ExtendedContactCommon ecc(ec2.mContactId.c_str(), ec2.mPath, ec2.mCallId.c_str(), ec2.mLineValueCopy.c_str());
	return compare(ec1, ec2.mAlias, ecc,
		       ec2.mCSeq, ec2.mExpireAt, ec2.mQ, ec2.mSipUri, ec2.mUpdatedTime);
}

bool compare(const Record &r1, const Record &r2) {
	auto ec1 = r1.getExtendedContacts();
	auto ec2 = r2.getExtendedContacts();
	if (ec1.size() != ec2.size()) BAD("ecc size :" << ec1.size() << " / " << ec2.size());

	return compare(firstContact(r1), firstContact(r2));
}


sip_path_t *path_fromstl(su_home_t *h, const std::list<std::string> &path) {
	sip_path_t *sip_path=NULL;
	for (auto it=path.rbegin(); it != path.rend(); ++it) {
		sip_path_t *p=sip_path_format(h, "%s", it->c_str());
		p->r_next=sip_path;
		sip_path=p;
	}

	return sip_path;
}


struct SofiaHome {
	su_home_t *h;
	SofiaHome() {
		h = new su_home_t;
		su_home_init(h);
	}
	~SofiaHome() {
		su_home_deinit(h);
		delete(h);
	}
};
#endif