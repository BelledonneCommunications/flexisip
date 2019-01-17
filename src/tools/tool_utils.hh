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

#pragma once

#include "../recordserializer.hh"
#include <flexisip/logmanager.hh>
#include <memory>
#include <map>
#include <iostream>
#include <cstring>

#define BAD(reason)                                                                                                    \
	do {                                                                                                               \
		std::cout << reason << std::endl;                                                                              \
		exit(-1);                                                                                                      \
	} while (0)

namespace flexisip {

void init_tests() {
	flexisip_sUseSyslog = false;
	flexisip::log::preinit(flexisip_sUseSyslog, flexisip::log::debug, 0, "test");
	flexisip::log::initLogs(flexisip_sUseSyslog, "debug", "error", false, false);
	flexisip::log::updateFilter("%Severity% >= debug");

	Record::sLineFieldNames = {"+sip.instance", "pn-tok", "line"};
	Record::sMaxContacts = 10;
}

ExtendedContact &firstContact(const Record &r) {
	return *r.getExtendedContacts().cbegin()->get();
}

std::ostream &operator<<(std::ostream &stream, const std::list<std::string> &str) {
	for (auto it = str.cbegin(); it != str.cend(); ++it) {
		if (it != str.cbegin())
			stream << ",";
		stream << *it;
	}
	return stream;
}

template <typename CompT> inline void check(const std::string &name, const CompT &v1, const CompT &v2) {
	if (v1 != v2) std::cout << name << " X" << v1 << "X / X" << v2 << "X" << std::endl;
}

bool compare(const ExtendedContact &ec1, bool alias, const ExtendedContactCommon &common, uint32_t cseq,
			 time_t expireat, float q, const std::string &sipuri, time_t updatedTime) {
	check("alias", ec1.mAlias, alias);
	check("callid", ec1.mCallId, common.mCallId);
	check("contactid", ec1.mContactId, common.mContactId);
	check("line", ec1.mUniqueId, common.mUniqueId);
	check("path", ec1.mPath, common.mPath);
	check("cseq", ec1.mCSeq, cseq);
	check("mExpireAt", ec1.mExpireAt, expireat);
	check("mQ", ec1.mQ, q);
	check("mSipUri", ExtendedContact::urlToString(ec1.mSipContact->m_url), sipuri);
	check("mUpdatedTime", ec1.mUpdatedTime, updatedTime);

	return true;
}

bool compare(const ExtendedContact &ec1, const ExtendedContact &ec2) {
	ExtendedContactCommon ecc(ec2.mContactId.c_str(), ec2.mPath, ec2.mCallId.c_str(), ec2.mUniqueId.c_str());
	return compare(ec1, ec2.mAlias, ecc, ec2.mCSeq, ec2.mExpireAt, ec2.mQ, ExtendedContact::urlToString(ec2.mSipContact->m_url),
			ec2.mUpdatedTime);
}

bool compare(const Record &r1, const Record &r2) {
	auto ec1 = r1.getExtendedContacts();
	auto ec2 = r2.getExtendedContacts();
	if (ec1.size() != ec2.size()) BAD("ecc size :" << ec1.size() << " / " << ec2.size());

	return compare(firstContact(r1), firstContact(r2));
}

sip_path_t *path_fromstl(su_home_t *h, const std::list<std::string> &path) {
	sip_path_t *sip_path = NULL;
	for (auto it = path.rbegin(); it != path.rend(); ++it) {
		sip_path_t *p = sip_path_format(h, "%s", it->c_str());
		p->r_next = sip_path;
		sip_path = p;
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
		delete (h);
	}
};

}