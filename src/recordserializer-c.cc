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

#include <sstream>
#include "common.hh"
#include "registrardb.hh"
#include "recordserializer.hh"
#include <sofia-sip/sip_protos.h>

using namespace std;

/**
 * 	#<sip:guillaume@domain:port;transport=toto;e=titi>#45#q=1#45646#1325691167#ci=call_id#5
	##<sip:guillaume@domain:port;transport=toto;ee=titi>#45#q=1#4645465#1325691167#call_id#8";
 */
bool RecordSerializerC::parse(const char *str, int len, Record *r){
	if (!str) return true;

	char *empty;
	char *rc=strndup(str, len+1);
	char *rcp=rc;
	rc[len]='\0';
	int i=1;

	while (NULL != (empty=strsep(&rc, "#"))){
		char *sip_contact=strsep(&rc, "#");
		char *expire=strsep(&rc, "#");
		char *q=strsep(&rc, "#");
		char *contactId=strsep(&rc, "#");
		char *route=strsep(&rc, "#");
		char *lineValue=strsep(&rc, "#");
		char *update_time=strsep(&rc, "#");
		char *call_id=strsep(&rc, "#");
		char *cseq=strsep(&rc, "#");

		if (empty[0] != '\0' || !sip_contact || sip_contact[0] != '<' || !expire || !update_time || !call_id || !cseq){
			LOGE("Invalid serialized contact %i %s",i, str);
			free(rc);
			return false;
		}

		r->bind(sip_contact, contactId, route, lineValue, q?atof(q):0, atol(expire), call_id, atoi(cseq), atol(update_time));
		++i;
	}

	free(rcp);
	return true;
}

// #sipuri#expireAt#q#lineValue#updateTime#callId#cseq
bool RecordSerializerC::serialize(Record *r, string &serialized){
	if (!r) return true;

	list<extended_contact *> contacts=r->getExtendedContacts();
	list<extended_contact *>::iterator it;
	ostringstream oss;

	int i=0;
	for (it=contacts.begin(); it != contacts.end(); ++it){
		extended_contact *ec=(*it);
		if (i != 0) oss << "#";
		oss << "#" << ec->mSipUri << "#" << ec->mExpireAt << "#" <<ec->mQ;
		oss << "#" << ec->mContactId;
		oss << "#"; if (ec->mRoute) oss << ec->mRoute;
		oss << "#"; if (ec->mLineValueCopy) oss << ec->mLineValueCopy;
		oss << "#" << ec->mUpdatedTime;
		oss << "#" << ec->mCallId << "#" << ec->mCSeq;
		++i;
	}

	// Unfortunately, make 2 copies
	serialized.assign(oss.str());
	return true;
}

