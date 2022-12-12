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

#include <flexisip/utils/sip-uri.hh>
#include <flexisip/registrar/binding-parameters.hh>
#include <flexisip/registrar/change-set.hh>

#include "tool_utils.hh"

using namespace std;
using namespace flexisip;

int test_bind_with_ecc(ExtendedContactCommon& ecc,
                       const unique_ptr<RecordSerializer>& serializer,
                       string contact,
                       time_t expireat,
                       float quality,
                       long cseq,
                       time_t now,
                       bool alias,
                       sip_accept_t* accept) {
	Record initial(SipUri{});

	list<string> acceptHeaders;
	while (accept != NULL) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}

	initial.update(ecc, contact.c_str(), expireat, quality, cseq, now, alias, acceptHeaders, false, NULL);
	if (!compare(firstContact(initial), alias, ecc, cseq, expireat, quality, contact, now)) {
		cerr << "Initial and parameters differ" << endl;
		return -1;
	}

	string serialized;
	if (!serializer->serialize(&initial, serialized, true)) {
		cerr << "Failed serializing" << endl;
		return -1;
	}

	Record final(SipUri{});
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

int test_bind_without_ecc(ExtendedContactCommon& ecc,
                          const unique_ptr<RecordSerializer>& serializer,
                          sip_contact_t* contacts,
                          sip_path_t* path,
                          int globalexpire,
                          const char* callid,
                          string contact,
                          time_t expireat,
                          float quality,
                          long cseq,
                          time_t now,
                          bool alias,
                          sip_accept_t* accept) {
	Record initial(SipUri{});

	msg_t* msg = msg_create(sip_default_mclass(), 0);
	su_home_t* homeSip = msg_home(msg);
	sip_t* sip = sip_object(msg);

	sip->sip_contact = sip_contact_dup(homeSip, contacts);
	sip->sip_contact->m_next = nullptr;
	sip->sip_accept = sip_accept_dup(homeSip, accept);
	sip->sip_from = sip_from_create(homeSip, reinterpret_cast<url_string_t*>(contacts->m_url));
	sip->sip_path = sip_path_dup(homeSip, path);
	sip->sip_call_id = sip_call_id_make(homeSip, callid);
	sip->sip_expires = sip_expires_create(homeSip, now);
	sip->sip_cseq = sip_cseq_create(homeSip, cseq, sip_method_unknown, nullptr);

	BindingParameters parameters;
	parameters.globalExpire = globalexpire;
	parameters.alias = alias;
	initial.update(sip, parameters, nullptr);

	msg_unref(msg);

	if (!compare(firstContact(initial), alias, ecc, cseq, expireat, quality, contact, now)) {
		cerr << "Initial and parameters differ" << endl;
		return -1;
	}

	string serialized;
	if (!serializer->serialize(&initial, serialized, true)) {
		cerr << "Failed serializing" << endl;
		return -1;
	} else {
		cout << "Serialized size: " << serialized.length() << endl;
	}

	Record final(SipUri{});
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

int main(int argc, char** argv) {
	if (argc != 2) {
		cerr << "bad usage" << endl;
		exit(-1);
	}
	init_tests();
	auto serializer = unique_ptr<RecordSerializer>(RecordSerializer::create(argv[1]));
	if (!serializer) {
		cerr << "bad serializer" << argv[1] << endl;
		exit(-1);
	}

	int expire_delta = 1000;
	list<string> paths{"path1", "path2", "path3"};
	string contactid{"192.168.0.1:5223"};
	string callid{"callid"};
	string line{"line"};
	string contact = "sip:" + contactid + ";line=" + line;
	string contactWithChev = "<" + contact + ">";
	uint32_t cseq = 123456;
	time_t now = time(NULL);
	time_t expireat = now + expire_delta;
	float quality = 1;
	bool alias = false;

	ExtendedContactCommon ecc(paths, callid.c_str(), line.c_str());

	sip_contact_t* sip_contact =
	    sip_contact_format(home.h, "<%s>;q=%f;expires=%d", contact.c_str(), quality, expire_delta);
	sip_path_t* sip_path = path_fromstl(home.h, paths);
	sip_accept_t* accept = NULL;

	if (test_bind_with_ecc(ecc, serializer, contact, expireat, quality, cseq, now, alias, accept)) {
		BAD("failure in bind with ecc");
	}

	if (test_bind_without_ecc(ecc, serializer, sip_contact, sip_path, 55555, callid.c_str(), contactWithChev.c_str(),
	                          expireat, quality, cseq, now, alias, accept)) {
		BAD("failure in bind without ecc");
	}

	cout << "success" << endl;

	bctbx_uninit_logger();
	return 0;
}
