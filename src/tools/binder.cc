/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include "registrardb-internal.hh"
#include "registrardb.hh"
#include "tool_utils.hh"

using namespace std;
using namespace flexisip;

struct MyListener : public ContactUpdateListener {
	virtual void onRecordFound(Record* r) override {
		const auto& ec = *r->getExtendedContacts().oldest();
		check("expire", atol(params.sip.contact->m_expires), ec->getSipExpires());
	}
	virtual void onError() override {
		BAD("RegistrarDbListener:error");
	}
	virtual void onInvalid() override {
		BAD("RegistrarDbListener:invalid");
	}
	virtual void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
	}
};

SofiaHome home;

void checkExpireHandling() {
	check("resolve expire1", ExtendedContact::resolveExpire(NULL, 5), 5);
	check("resolve expire2", ExtendedContact::resolveExpire(NULL, -1), -1);
	check("resolve expire3", ExtendedContact::resolveExpire("5", 6), 5);
	check("resolve expire4", ExtendedContact::resolveExpire("5", -1), 5);
}

static sip_contact_t* uid_ct(const char* urlparams, const char* ctparams) {
	return sip_contact_format(home.h, "<%s%s>%s", "sip:localhost:12345", urlparams, ctparams);
}
void checkUniqueIdExtraction() {
#define UID_PARAM theparam
	string theparam = "UID_PARAM";
	check("+sip.instance in ct param", Record::extractUniqueId(uid_ct("", ";+sip.instance=UID_PARAM")), theparam);

	check("+sip.instance in url param", Record::extractUniqueId(uid_ct(";+sip.instance=UID_PARAM", "")), theparam);

	check("line in ct param", Record::extractUniqueId(uid_ct("", ";line=UID_PARAM")), theparam);

	check("line url param", Record::extractUniqueId(uid_ct(";line=UID_PARAM", "")), theparam);
}
int main(int argc, char** argv) {
	init_tests();

	checkExpireHandling();
	checkUniqueIdExtraction();

	int expire_delta = 1000;
	list<string> paths{"path1", "path2", "path3"};
	string contactid{"ip:5223"};
	string callid{"callid"};
	string line{"line"};
	string contact = "sip:" + contactid + ";line=" + line;
	string contactWithChev = "<" + contact + ">";
	uint32_t cseq = 123456;
	float quality = 1;
	bool alias = false;
	const url_t* from = url_make(home.h, "sip:guillaume@bc");

	ExtendedContactCommon ecc(contactid.c_str(), paths, callid.c_str(), line.c_str());

	sip_contact_t* sip_contact =
	    sip_contact_format(home.h, "<%s>;q=%f;expires=%d", contact.c_str(), quality, expire_delta);
	sip_path_t* sip_path = path_fromstl(home.h, paths);
	sip_accept_t* accept = NULL;

	RegistrarDbInternal registrar("preferred_ip");
	RegistrarDb::BindParameters params(
	    RegistrarDb::BindParameters::SipParams(from, sip_contact, callid.c_str(), cseq, sip_path, accept), 55555,
	    alias);
	auto listener = make_shared<MyListener>(params);
	registrar.bind(params, listener);

	registrar.clearAll();
	cout << "success" << endl;
	return 0;
}
