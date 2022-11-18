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

#include <sofia-sip/sip_protos.h>

#include <flexisip/common.hh>

#include "cJSON.h"
#include "registrar/extended-contact.hh"

using namespace std;
using namespace flexisip;

#define CHECK(msg, test)                                                                                               \
	if (test) {                                                                                                        \
		SLOGE << "Invalid serialized contact " << i << "\n" << str << msg;                                             \
		cJSON_Delete(root);                                                                                            \
		return false;                                                                                                  \
	}

static inline char* parseOptionalField(cJSON* json, const char* field) {
	cJSON* cObj = cJSON_GetObjectItem(json, field);
	return cObj ? cObj->valuestring : NULL;
}

bool RecordSerializerJson::parse(const char* str, [[maybe_unused]] int len, Record* r) {
	if (!str) return true;

	cJSON* root = cJSON_Parse(str);
	if (!root) {
		LOGE("Error parsing JSON contact: [%s]", cJSON_GetErrorPtr());
		return false;
	}
	cJSON* contact = cJSON_GetObjectItem(root, "contacts");

	int i = 0;
	while (contact && contact->child) {
		const char* sip_contact = cJSON_GetObjectItem(contact->child, "contact")->valuestring;
		time_t expire = cJSON_GetObjectItem(contact->child, "expires-at")->valuedouble;
		float q = cJSON_GetObjectItem(contact->child, "q")->valuedouble;
		const char* lineValue = parseOptionalField(contact->child, "unique-id");
		const char* route = parseOptionalField(contact->child, "path");
		const char* contactId = cJSON_GetObjectItem(contact->child, "contact-id")->valuestring;
		time_t update_time = cJSON_GetObjectItem(contact->child, "update-time")->valuedouble;
		char* call_id = cJSON_GetObjectItem(contact->child, "call-id")->valuestring;
		int cseq = cJSON_GetObjectItem(contact->child, "cseq")->valueint;
		bool alias = cJSON_GetObjectItem(contact->child, "alias")->valueint != 0;
		cJSON* path = cJSON_GetObjectItem(contact->child, "path");
		cJSON* accept = cJSON_GetObjectItem(contact->child, "accept");

		CHECK(" no sip_contact", !sip_contact || sip_contact[0] == 0);
		CHECK(" no contactId", !contactId || contactId[0] == 0);
		// CHECK_VAL("malformed sip contact", sip_contact[0] != '<', sip_contact);
		CHECK("no expire", !expire);
		CHECK("no updatetime", !update_time);
		CHECK("no callid", !call_id || call_id[0] == 0);
		CHECK("no callid", !call_id || call_id[0] == 0);

		std::list<std::string> stlpath;
		if (route) stlpath.push_back(route);
		for (int p = 0; p < cJSON_GetArraySize(path); p++) {
			stlpath.push_back(cJSON_GetArrayItem(path, p)->valuestring);
		}

		std::list<std::string> acceptHeaders;
		for (int p = 0; p < cJSON_GetArraySize(accept); p++) {
			acceptHeaders.push_back(cJSON_GetArrayItem(accept, p)->valuestring);
		}

		ExtendedContactCommon ecc(stlpath, call_id, lineValue);
		r->update(ecc, sip_contact, expire, q, cseq, update_time, alias, acceptHeaders, false, NULL);
		contact = contact->next;
		++i;
	}

	cJSON_Delete(root);
	return true;
}

bool RecordSerializerJson::serialize(Record* r, string& serialized, bool log) {
	if (!r) return true;

	auto ecs = r->getExtendedContacts();
	cJSON* root = cJSON_CreateObject();
	cJSON* contacts = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "contacts", contacts);
	for (auto it = ecs.begin(); it != ecs.end(); ++it) {
		cJSON* c = cJSON_CreateObject();
		cJSON_AddItemToArray(contacts, c);
		cJSON* path = cJSON_CreateArray();

		cJSON* acceptHeaders = cJSON_CreateArray();

		shared_ptr<ExtendedContact> ec = (*it);
		cJSON_AddStringToObject(c, "contact", ExtendedContact::urlToString(ec->mSipContact->m_url).c_str());
		cJSON_AddItemToObject(c, "path", path);
		cJSON_AddNumberToObject(c, "expires-at", ec->mExpireAt);
		cJSON_AddNumberToObject(c, "q", ec->mQ ? ec->mQ : 0);
		cJSON_AddStringToObject(c, "unique-id", ec->mKey.str().c_str());

		cJSON_AddStringToObject(c, "user-agent", ec->getUserAgent().c_str());

		cJSON_AddStringToObject(c, "call-id", ec->callId());
		cJSON_AddNumberToObject(c, "cseq", ec->mCSeq);
		cJSON_AddItemToObject(c, "accept", acceptHeaders);
		cJSON_AddNumberToObject(c, "alias", ec->mAlias ? 1 : 0);
		cJSON_AddNumberToObject(c, "update-time", ec->mUpdatedTime);

		for (auto pit = ec->mPath.cbegin(); pit != ec->mPath.cend(); ++pit) {
			cJSON* pitem = cJSON_CreateString(pit->c_str());
			cJSON_AddItemToArray(path, pitem);
		}
		for (auto pit = ec->mAcceptHeader.cbegin(); pit != ec->mAcceptHeader.cend(); ++pit) {
			cJSON* pitem = cJSON_CreateString(pit->c_str());
			cJSON_AddItemToArray(acceptHeaders, pitem);
		}
	}

	char* contacts_str = cJSON_Print(root);
	if (!contacts_str) return false;
	serialized.assign(contacts_str);
	if (log) SLOGI << "Serialized contact: " << serialized;

	cJSON_Delete(root);
	free(contacts_str);
	return true;
}
