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

#include "flexisip/common.hh"

#include "recordserializer-protobuf.pb.h"
#include "registrar/extended-contact.hh"
#include "utils/string-utils.hh"

using namespace std;
using namespace flexisip;

// See .proto file for description of the format.

RecordSerializerPb::RecordSerializerPb() {
	GOOGLE_PROTOBUF_VERIFY_VERSION;
}

bool RecordSerializerPb::parse(const char* str, int len, Record* r) {
	if (!str) return true;

	RecordContactListPb contacts;
	const string container(str, len);
	if (!contacts.ParseFromString(container)) {
		return false;
	}

	for (int i = 0; i < contacts.contact_size(); ++i) {
		const RecordContactPb& c = contacts.contact(i);
		list<string> stlpath;
		if (c.has_route()) stlpath.push_back(c.route());
		for (int p = 0; p < c.path_size(); ++p) {
			stlpath.push_back(c.path(p));
		}

		list<string> acceptHeaders;
		for (int p = 0; p < c.accept_header_size(); ++p) {
			acceptHeaders.push_back(c.accept_header(p));
		}

		/* Some Protobuf serializer versions were encoding the Contact-URI as Contact header.
		   Workaround it by removing first and last characters if the URI is enclosed by '<>'. */
		auto uri = c.uri();
		if (uri.size() >= 2 && uri[0] == '<' && uri[uri.size() - 1] == '>') {
			uri = uri.substr(1, uri.size() - 2);
		}

		ExtendedContactCommon ecc(stlpath, c.call_id().c_str(),
		                          c.has_line_value_copy() ? c.line_value_copy().c_str() : NULL);
		r->update(ecc, uri.c_str(), (time_t)c.expires_at(), c.q(), (uint32_t)c.cseq(), c.update_time(), false,
		          acceptHeaders, c.has_used_as_route() ? c.used_as_route() : false, NULL);
	}
	return true;
}

bool RecordSerializerPb::serialize(Record* r, string& serialized, bool log) {
	if (!r) return true;

	RecordContactListPb pbContacts;
	auto contacts = r->getExtendedContacts();
	auto it = contacts.begin();
	for (it = contacts.begin(); it != contacts.end(); ++it) {
		auto ec = *it;
		RecordContactPb* c = pbContacts.add_contact();
		c->set_uri(ExtendedContact::urlToString(ec->mSipContact->m_url));
		c->set_contact_id("deprecated");
		if (!ec->mKey.isPlaceholder())
			c->set_line_value_copy(ec->mKey.str().c_str());
		c->set_expires_at(ec->getSipExpireTime());
		if (ec->mQ) c->set_q(ec->mQ);
		c->set_update_time(ec->getRegisterTime());
		c->set_call_id(ec->callId());
		c->set_cseq(ec->mCSeq);
		for (auto pit = ec->mPath.cbegin(); pit != ec->mPath.cend(); ++pit) {
			c->add_path(*pit);
		}
		for (auto pit = ec->mAcceptHeader.cbegin(); pit != ec->mAcceptHeader.cend(); ++pit) {
			c->add_accept_header(*pit);
		}
		c->set_used_as_route(ec->mUsedAsRoute);
	}

	if (log) SLOGI << "Serialized " << pbContacts.DebugString() << "initialized: " << pbContacts.IsInitialized();
	return pbContacts.SerializeToString(&serialized);
}
