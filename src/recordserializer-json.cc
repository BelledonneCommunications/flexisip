/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2012 Belledonne Communications SARL.
    Author: Guillaume Beraudo

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

#include "common.hh"
#include "registrardb.hh"
#include "recordserializer.hh"
#include <sofia-sip/sip_protos.h>
#include "cJSON.h"

using namespace std;

static inline char *parseOptionalField(const cJSON *json, const char *field){
	cJSON *cObj=cJSON_GetObjectItem(json->child,field);
	return cObj?cObj->valuestring:NULL;
}

bool RecordSerializerJson::parse(const char *str, int len, Record *r){
	if (!str) return true;

	cJSON *root = cJSON_Parse(str);
	if (!root) {
		LOGE("Error parsing JSON contact: [%s]",cJSON_GetErrorPtr());
		return false;
	}
	cJSON *contact = cJSON_GetObjectItem(root,"contacts");


	int i=0;
	while (contact && contact->child){
		char *sip_contact=cJSON_GetObjectItem(contact->child,"uri")->valuestring;
		time_t expire=cJSON_GetObjectItem(contact->child,"expires_at")->valuedouble;
		float q=cJSON_GetObjectItem(contact->child,"q")->valuedouble;
		const char *lineValue=parseOptionalField(contact->child, "line_value_copy");
		const char *route=parseOptionalField(contact->child, "route");
		const char *contactId=parseOptionalField(contact->child, "contact_id");
		time_t update_time=cJSON_GetObjectItem(contact->child,"update_time")->valuedouble;
		char *call_id=cJSON_GetObjectItem(contact->child,"call_id")->valuestring;
		int cseq=cJSON_GetObjectItem(contact->child,"cseq")->valueint;
		bool alias=cJSON_GetObjectItem(contact->child,"alias")->valueint != 0;
		cJSON *path=cJSON_GetObjectItem(contact->child,"path");


		if (!sip_contact || sip_contact[0] != '<' || !expire || !update_time || !call_id || !cseq || !path){
			LOGE("Invalid redis contact %i %s",i, str);
			cJSON_Delete(root);
			return false;
		}

		std::list<std::string> stlpath;
		if (route) stlpath.push_back(route);
		for (int p = 0 ; p < cJSON_GetArraySize(path) ; p++) {
			stlpath.push_back(cJSON_GetArrayItem(path, p)->valuestring);
		}

		ExtendedContactCommon ecc(contactId, stlpath, call_id, lineValue);
		r->bind(ecc, sip_contact, q, expire, cseq, update_time, alias);
		contact=contact->next;
		++i;
	}

	cJSON_Delete(root);
	return true;
}

bool RecordSerializerJson::serialize(Record *r, string &serialized){
	if (!r) return true;

	auto ecs=r->getExtendedContacts();
	cJSON *root=cJSON_CreateObject();
	cJSON *contacts=cJSON_CreateArray();
	cJSON_AddItemToObject(root, "contacts", contacts);
	for (auto it=ecs.begin(); it != ecs.end(); ++it){
		cJSON *c=cJSON_CreateObject();
		cJSON_AddItemToArray(contacts,c);
		cJSON *path=cJSON_CreateArray();
		cJSON_AddItemToObject(c, "path", path);

		shared_ptr<ExtendedContact> ec=(*it);
		cJSON_AddStringToObject(c,"uri",ec->mSipUri.c_str());
		cJSON_AddNumberToObject(c,"expires_at",ec->mExpireAt);
		cJSON_AddNumberToObject(c,"q",ec->mQ?ec->mQ : 0);
		if (ec->line()) cJSON_AddStringToObject(c,"line_value_copy",ec->line());
		cJSON_AddStringToObject(c,"contact_id",ec->contactId());
		cJSON_AddNumberToObject(c,"update_time",ec->mUpdatedTime);
		cJSON_AddStringToObject(c,"call_id",ec->callId());
		cJSON_AddNumberToObject(c,"cseq",ec->mCSeq);
		cJSON_AddNumberToObject(c,"alias",ec->mAlias? 1: 0);

		for (auto pit=ec->mCommon.mPath.cbegin(); pit != ec->mCommon.mPath.cend(); ++pit) {
			cJSON *pitem = cJSON_CreateString(pit->c_str());
			cJSON_AddItemToArray(path, pitem);
		}
	}

	char *contacts_str=cJSON_PrintUnformatted(root);
	if (contacts_str) serialized.assign(contacts_str);

	cJSON_Delete(root);
	free(contacts_str);
	return true;
}

