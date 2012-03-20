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

		if (!sip_contact || sip_contact[0] != '<' || !expire || !update_time || !call_id || !cseq){
			LOGE("Invalid redis contact %i %s",i, str);
			cJSON_Delete(root);
			return false;
		}

		r->bind(sip_contact, contactId, route, lineValue, q, expire, call_id, cseq, update_time);
		contact=contact->next;
		++i;
	}

	cJSON_Delete(root);
	return true;
}

bool RecordSerializerJson::serialize(Record *r, string &serialized){
	if (!r) return true;

	list<extended_contact *> ecs=r->getExtendedContacts();
	list<extended_contact *>::iterator it;
	cJSON *root=cJSON_CreateObject();
	cJSON *contacts=cJSON_CreateArray();
	cJSON_AddItemToObject(root, "contacts", contacts);
	for (it=ecs.begin(); it != ecs.end(); ++it){
		cJSON *c=cJSON_CreateObject();
		cJSON_AddItemToArray(contacts,c);
		extended_contact *ec=(*it);
		cJSON_AddStringToObject(c,"uri",ec->mSipUri);
		cJSON_AddNumberToObject(c,"expires_at",ec->mExpireAt);
		cJSON_AddNumberToObject(c,"q",ec->mQ?ec->mQ : 0);
		if (ec->mLineValueCopy) cJSON_AddStringToObject(c,"line_value_copy",ec->mLineValueCopy);
		if (ec->mRoute) cJSON_AddStringToObject(c,"route",ec->mRoute);
		cJSON_AddStringToObject(c,"contact_id",ec->mContactId);
		cJSON_AddNumberToObject(c,"update_time",ec->mUpdatedTime);
		cJSON_AddStringToObject(c,"call_id",ec->mCallId);
		cJSON_AddNumberToObject(c,"cseq",ec->mCSeq);
	}

	char *contacts_str=cJSON_PrintUnformatted(root);
	if (contacts_str) serialized.assign(contacts_str);

	cJSON_Delete(root);
	free(contacts_str);
	return true;
}

