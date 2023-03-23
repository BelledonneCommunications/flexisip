/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL.
    Author: Guillaume BIENKOWSKI

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
#include <msgpack.hpp>
#include <string.h>

using namespace msgpack;
using namespace flexisip;

RecordSerializerMsgPack::RecordSerializerMsgPack() {
}

struct MsgPackContact {
	std::string mContactId;
	std::string mCallId;
	std::string mUniqueId;
	std::list<std::string> mPath;
	std::string mSipUri;
	float mQ;
	time_t mExpireTime;
	time_t mRegisterTime;
	uint32_t mCSeq;
	bool mAlias;
	std::list<std::string> mAcceptHeader;
	bool mUsedAsRoute;
	std::string line;

	MSGPACK_DEFINE(mContactId,
	               mCallId,
	               mUniqueId,
	               mPath,
	               mSipUri,
	               mQ,
	               mExpireTime,
	               mRegisterTime,
	               mCSeq,
	               mAlias,
	               mAcceptHeader,
	               mUsedAsRoute,
	               line);
};

bool RecordSerializerMsgPack::parse(const char* str, int len, Record* r) {
	if (!str) return true;

	auto unpacked_obj = unpack(str, len);
	auto obj = unpacked_obj.get();
	std::vector<MsgPackContact> list;
	obj.convert(list);

	for (auto it = list.begin(); it != list.end(); ++it) {
		MsgPackContact& c = *it;
		ExtendedContactCommon ecc(c.mContactId.c_str(), c.mPath, c.mCallId.c_str(), c.line.c_str());
		r->update(ecc, c.mSipUri.c_str(), c.mExpireTime, c.mQ, c.mCSeq, c.mRegisterTime, c.mAlias, c.mPath,
		          c.mUsedAsRoute, 0);
	}

	return true;
}

bool RecordSerializerMsgPack::serialize(Record* r, std::string& serialized, bool log) {

	if (!r) return true;

	std::stringstream ss;
	auto extContacts = r->getExtendedContacts();
	std::vector<MsgPackContact> contacts;
	for (auto it = extContacts.begin(); it != extContacts.end(); ++it) {
		auto c = *it;
		SLOGI << "CSeq " << c->mCSeq;
		contacts.push_back(MsgPackContact{
		    c->mContactId, c->mCallId, c->mUniqueId, c->mPath, ExtendedContact::urlToString(c->mSipContact->m_url),
		    c->mQ, c->mExpireTime, c->mRegisterTime, c->mCSeq, c->mAlias, c->mAcceptHeader, c->mUsedAsRoute, c->line()});
	}
	pack(ss, contacts);
	serialized = ss.str();
	if (log) {
		SLOGI << "Serialized size:" << ss.str().length();
	}
	return true;
}
