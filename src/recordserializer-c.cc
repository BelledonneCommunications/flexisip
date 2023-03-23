/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "recordserializer.hh"

#include <sstream>

#include <sofia-sip/sip_protos.h>

#include "flexisip/common.hh"

#include "registrar/extended-contact.hh"

using namespace std;
using namespace flexisip;

#define CHECK(msg, test)                                                                                               \
	if (test) {                                                                                                        \
		SLOGE << "Invalid serialized contact " << i << " " << msg;                                                     \
		free(rc);                                                                                                      \
		return false;                                                                                                  \
	}
// #define CHECK_VAL(msg, test, value) if (test) { SLOGE << "Invalid serialized contact " << i << " " << msg << " " <<
//  value; free(rc); return false; }

/**
 * 	#<sip:guillaume@domain:port;transport=toto;e=titi>#45#q=1#45646#1325691167#ci=call_id#5
    ##<sip:guillaume@domain:port;transport=toto;ee=titi>#45#q=1#4645465#1325691167#call_id#8";
 */
bool RecordSerializerC::parse(const char* str, int len, Record* r) {
	if (!str) return true;

	char* empty;
	char* rc = strndup(str, len + 1);
	char* rcp = rc;
	rc[len] = '\0';
	int i = 1;

	while (NULL != (empty = strsep(&rc, "#"))) {
		char* sip_contact = strsep(&rc, "#");
		char* expire = strsep(&rc, "#");
		char* q = strsep(&rc, "#");
		char* contactId = strsep(&rc, "#");
		char* route = strsep(&rc, "#");
		char* lineValue = strsep(&rc, "#");
		char* update_time = strsep(&rc, "#");
		char* call_id = strsep(&rc, "#");
		char* cseq = strsep(&rc, "#");
		char* alias = strsep(&rc, "#");
		char* path = strsep(&rc, "#");
		char* accept = strsep(&rc, "#");

		CHECK("empty", empty[0] != '\0');
		CHECK(" no sip_contact", !sip_contact || sip_contact[0] == 0);
		CHECK(" no contactId", !contactId || contactId[0] == 0);
		// CHECK_VAL("malformed sip contact", sip_contact[0] != '<', sip_contact);
		CHECK("no expire", !expire || expire[0] == 0);
		CHECK("no updatetime", !update_time || update_time[0] == 0);
		CHECK("no callid", !call_id || call_id[0] == 0);
		CHECK("no cseq", !cseq);

		std::list<std::string> stlpath;
		if (route && route[0] != 0) stlpath.push_back(route);
		while (NULL != (empty = strsep(&path, ","))) {
			stlpath.push_back(empty);
		}

		std::list<std::string> acceptHeaders;
		while (NULL != (empty = strsep(&accept, ","))) {
			acceptHeaders.push_back(empty);
		}

		ExtendedContactCommon ecc(stlpath, call_id, lineValue);
		r->update(ecc, sip_contact, atol(expire), q ? atof(q) : 0, atoi(cseq), atol(update_time),
		          strcmp(alias, "true") == 0, acceptHeaders, false, NULL);
		++i;
	}

	free(rcp);
	return true;
}

// #sipuri#expireAt#q#lineValue#updateTime#callId#cseq
bool RecordSerializerC::serialize(Record* r, string& serialized, bool log) {
	if (!r) return true;

	auto contacts = r->getExtendedContacts();
	ostringstream oss;

	int i = 0;
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		shared_ptr<ExtendedContact> ec = *it;
		if (i != 0) oss << "#";
		oss << "#" << ec->mSipContact->m_url << "#" << ec->getSipExpireTime() << "#" << ec->mQ;
		oss << "#" << ec->contactId();
		oss << "#"; // route
		oss << "#";
		if (!ec->mKey.isPlaceholder()) oss << ec->mKey.str();
		oss << "#" << ec->getRegisterTime();
		oss << "#" << ec->callId() << "#" << ec->mCSeq << "#" << (ec->mAlias ? "true" : "false");
		string pathstr;
		for (auto pit = ec->mPath.cbegin(); pit != ec->mPath.cend(); ++pit) {
			if (pit != ec->mPath.cbegin()) pathstr += ",";
			pathstr += *pit;
		}
		oss << "#" << pathstr;
		string acceptstr;
		for (auto pit = ec->mAcceptHeader.cbegin(); pit != ec->mAcceptHeader.cend(); ++pit) {
			if (pit != ec->mAcceptHeader.cbegin()) acceptstr += ",";
			acceptstr += *pit;
		}
		oss << "#" << acceptstr;
		++i;
	}

	serialized.assign(oss.str());
	if (log) SLOGI << "Serialized contact: " << serialized;

	return true;
}
