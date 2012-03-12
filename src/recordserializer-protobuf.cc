/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2012  Belledonne Communications SARL.
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
#include "recordserializer-protobuf.pb.h"
#include <sofia-sip/sip_protos.h>


// See .proto file for description of the format.

RecordSerializerPb::RecordSerializerPb(){
	GOOGLE_PROTOBUF_VERIFY_VERSION;
}


bool RecordSerializerPb::parse(const char *str, int len, Record *r){
	if (!str) return true;

	RecordContactListPb contacts;
	const string container(str, len);
	if (!contacts.ParseFromString(container)){
		return false;
	}

	for (int i = 0; i < contacts.contact_size(); ++i) {
	    const RecordContactPb& c = contacts.contact(i);
		r->bind(c.uri().c_str(),
				c.contact_id().c_str(),
				c.has_route()? c.route().c_str() : NULL,
				c.has_line_value_copy()? c.line_value_copy().c_str() : NULL,
				c.expires_at(),
				c.q(),
				c.call_id().c_str(),
				c.cseq(),
				c.update_time());
	}
	return true;
}


bool RecordSerializerPb::serialize(Record *r, string &serialized){
	if (!r)	return true;


	RecordContactListPb pbContacts;
	list<extended_contact *> contacts=r->getExtendedContacts();
	list<extended_contact *>::iterator it;
	for (it=contacts.begin(); it != contacts.end(); ++it){
		extended_contact *ec=(*it);
		RecordContactPb *c = pbContacts.add_contact();
		c->set_uri(ec->mSipUri);
		c->set_contact_id(ec->mContactId);
		if (ec->mRoute) c->set_route(ec->mRoute);
		if (ec->mLineValueCopy) c->set_line_value_copy(ec->mLineValueCopy);
		c->set_expires_at(ec->mExpireAt);
		if (ec->mQ) c->set_q(ec->mQ);
		c->set_update_time(ec->mUpdatedTime);
		c->set_call_id(ec->mCallId);
		c->set_cseq(ec->mCSeq);
	}

	pbContacts.SerializeToString(&serialized);
	return true;
}

