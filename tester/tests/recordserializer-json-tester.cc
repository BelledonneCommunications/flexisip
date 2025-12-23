/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <cstddef>
#include <ctime>
#include <ostream>
#include <sstream>

#include <sys/select.h>
#include <sys/un.h>

#include "bctoolbox/tester.h"
#include "lib/nlohmann-json-3-11-2/json.hpp"

#include "flexisip/utils/sip-uri.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

using json = nlohmann::json;

namespace flexisip::tester {
namespace {

const time_t kExpiresAt = getCurrentTime() + 259200; // An extended contact cannot be expired to be added to record

void compareRecords(const Record& record, const Record& recordRef, bool hasSameContactKeyValue = true) {
	const auto& contacts = record.getExtendedContacts();
	const auto& contactsRef = recordRef.getExtendedContacts();
	BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), contactsRef.size());
	auto itRef = contactsRef.begin();
	for (auto it = contacts.begin(); it != contacts.end(); ++it, ++itRef) {
		if (itRef->get()->route() == nullptr) {
			BC_ASSERT_PTR_NULL(it->get()->route());
		} else {
			BC_ASSERT_STRING_EQUAL(it->get()->route(), itRef->get()->route());
		}
		BC_ASSERT_CPP_EQUAL(it->get()->contactId(), itRef->get()->contactId());
		BC_ASSERT_STRING_EQUAL(it->get()->userAgent(), itRef->get()->userAgent());
		BC_ASSERT_CPP_EQUAL(it->get()->getRegisterTime(), itRef->get()->getRegisterTime());
		BC_ASSERT_CPP_EQUAL(it->get()->getExpireTime(), itRef->get()->getExpireTime());
		SipUri uri{it->get()->mSipContact->m_url};
		SipUri uriRef{itRef->get()->mSipContact->m_url};
		BC_ASSERT_CPP_EQUAL(uri.str(), uriRef.str());
		BC_ASSERT_CPP_EQUAL(it->get()->mAlias, itRef->get()->mAlias);
		BC_ASSERT_CPP_EQUAL(it->get()->mQ, itRef->get()->mQ);
		BC_ASSERT_CPP_EQUAL(it->get()->mCSeq, itRef->get()->mCSeq);
		vector accept(it->get()->mAcceptHeader.begin(), it->get()->mAcceptHeader.end());
		vector acceptRef(itRef->get()->mAcceptHeader.begin(), itRef->get()->mAcceptHeader.end());
		BC_ASSERT_TRUE(accept == acceptRef);
		BC_ASSERT_STRING_EQUAL(it->get()->callId(), itRef->get()->callId());
		if (hasSameContactKeyValue) {
			BC_ASSERT_TRUE(it->get()->mKey == itRef->get()->mKey);
		}
	};
}

Record createRecord() {
	SipUri aor{"sip:aor@sip.example.org"};
	auto cfg = ConfigManager{};
	Record::Config recordConfig(cfg);
	return Record{aor, recordConfig};
}

string createValidContact() {
	ostringstream validContact{};
	validContact << "{";
	validContact << "\"contacts\":";
	validContact << R"([
	    {
			"contact": "sip:username@[ipv6:address:]:50614;transport=tls",
			"path":	["sip:flexisip-staging-beta.linphone.org:5059;transport=tcp"],
)";
	validContact << R"(			"expires-at": )" << kExpiresAt << ",";
	validContact << R"(
			"q":	1.0,
			"unique-id":	"<urn:uuid:unique-id>",
			"user-agent":	"user agent",
			"call-id":	"callId",
			"cseq":	21,
			"accept":	["application/sdp"],
			"alias":	0,
			"update-time":	1767973510
		}
	])";
	validContact << "}";
	return validContact.str();
};

void parseValidContact() {
	auto validContact = createValidContact();
	list<string> paths = {"sip:flexisip-staging-beta.linphone.org:5059;transport=tcp"};
	string sipContact = "sip:username@[ipv6:address:]:50614;transport=tls";
	list<string> acceptHeaders = {"application/sdp"};
	string callId = "callId";
	string userAgent = "user agent";
	string uniqueId = "<urn:uuid:unique-id>";
	time_t expire = kExpiresAt;
	time_t update = 1767973510;
	// Valid contact
	{
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(validContact, record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, uniqueId);
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef);
	}
	// Valid without optional alias
	{
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("alias");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, uniqueId);
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef);
	}
	// Valid without optional accepted headers
	{
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("accept");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, uniqueId);
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, {}, false, nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef);
	}
	// Valid without optional user agent
	{
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("user-agent");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, uniqueId);
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
		compareRecords(record, recordRef);
	}
	// Valid without optional q
	{
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("q");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, uniqueId);
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef);
	}
	// Valid without optional unique-id
	{
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("unique-id");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, "");
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef, false);
	}
	// Valid without optional path
	{
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("path");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc({}, callId, uniqueId);
		recordRef.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef);
	}
	// Check that the entry names are case insensitive
	{
		string sipContactUppercase = "sip:USERNAME@[ipv6:address:]:50614;transport=tls";
		auto jsonValidContact = json::parse(validContact);
		jsonValidContact["contacts"][0].erase("contact");
		jsonValidContact["contacts"][0].push_back({"CONTACT", sipContactUppercase});
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_TRUE(recordSerializer.parse(jsonValidContact.dump(), record));

		auto recordRef = createRecord();
		ExtendedContactCommon ecc(paths, callId, uniqueId);
		recordRef.update(ecc, sipContactUppercase.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false,
		                 nullptr);
		const auto& contacts = recordRef.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent;
		compareRecords(record, recordRef);
	}
}

void parseInvalidContact() {
	auto validContact = createValidContact();
	auto jsonValidContact = json::parse(validContact);
	auto recordRef = createRecord();

	// Invalid JSON with final comma
	{
		ostringstream invalidContact{};
		invalidContact << "{";
		invalidContact << "\"contacts\":";
		invalidContact << R"([{
			"contact": "sip:username@[ipv6:address:]:50614;transport=tls",
			"path":	["sip:flexisip-staging-beta.linphone.org:5059;transport=tcp"],
)";
		invalidContact << R"(			"expires-at": )" << kExpiresAt << ",";
		invalidContact << R"(
			"q":	1.0,
			"unique-id":	"<urn:uuid:unique-id>",
			"user-agent":	"user agent",
			"call-id":	"callId",
			"cseq":	21,
			"accept":	["application/sdp"],
			"alias":	0,
			"update-time":	1767973510,
		}])";
		invalidContact << "}";
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.str(), record));
		compareRecords(record, recordRef);
	}
	// Missing SIP contact URI
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0].erase("contact");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
	// Empty SIP contact URI
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0]["contact"] = "";
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
	// Missing call-id
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0].erase("call-id");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
	// Empty call-id
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0]["call-id"] = "";
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
	// Missing expire
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0].erase("expires-at");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
	// Missing update time
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0].erase("update-time");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
	// Missing cseq
	{
		auto invalidContact = jsonValidContact;
		invalidContact["contacts"][0].erase("cseq");
		auto record = createRecord();
		RecordSerializerJson recordSerializer;
		BC_ASSERT_FALSE(recordSerializer.parse(invalidContact.dump(), record));
		compareRecords(record, recordRef);
	}
}

void recordAndStrForContactWithMultipleDevices(Record& record, string& str) {
	// Set data
	vector<const char*> sipContact{
	    "sip:username@[ipv6:address:1]:50614;transport=tls",
	    "sip:username@[ipv6:address:2]:53349;transport=tls",
	};
	string path = "sip:flexisip-staging-beta.linphone.org:5059;transport=tcp";
	vector<time_t> expire = {
	    kExpiresAt,
	    kExpiresAt + 42,
	};
	float q = 1.0;
	vector<string> uniqueId = {
	    "<urn:uuid:unique-id-1>",
	    "<urn:uuid:unique-id-2>",
	};
	vector<string> userAgent = {
	    "Linphone-Desktop/6.1.0-beta.131+f2f29a0d7 (laptop) ubuntu/24.04 Qt/6.10.0 LinphoneSDK/5.4.73",
	    "Linphone-Desktop/6.1.0-beta.131+f2f29a0d7 (MacBook-Air) macos/26.1.0 Qt/6.10.0 "
	    "LinphoneSDK/5.4.73",
	};
	vector<time_t> updateTime = {
	    1767973510,
	    1767975017,
	};
	vector<const char*> callId = {
	    "callId1",
	    "callId2",
	};
	int cseq = 21;
	bool alias = false;
	vector<list<string>> acceptHeaders{
	    {
	        "application/sdp",
	        "another/header",
	    },
	    {
	        "application/sdp",
	    },
	};

	// Fill string
	ostringstream contact{};
	contact << fixed << setprecision(1);
	contact << "{\"contacts\":";
	contact << "[{";
	for (size_t i = 0; i < sipContact.size(); i++) {
		contact << "\"contact\":\"" << sipContact.at(i) << "\",";
		contact << "\"path\":[\"" << path << "\"],";
		contact << "\"expires-at\":" << expire.at(i) << ",";
		contact << "\"q\":" << q << ",";
		contact << "\"unique-id\":\"" << uniqueId.at(i) << "\",";
		contact << "\"user-agent\":\"" << userAgent.at(i) << "\",";
		contact << "\"call-id\":\"" << callId.at(i) << "\",";
		contact << "\"cseq\":" << cseq << ",";
		contact << "\"accept\":[";
		for (auto it = acceptHeaders.at(i).begin(); it != acceptHeaders.at(i).end(); ++it) {
			contact << "\"" << *it << "\"";
			if (next(it) != acceptHeaders.at(i).end()) contact << ", ";
		}
		contact << "],";
		contact << "\"alias\":" << alias << ",";
		contact << "\"update-time\":" << updateTime.at(i) << "";
		if (i != sipContact.size() - 1) contact << "},{";
	}
	contact << "}]}";
	auto jsonContact = json::parse(contact.str());
	str = jsonContact.dump(1, '\t');

	// Update record
	list paths = {path};
	for (size_t i = 0; i < sipContact.size(); i++) {
		ExtendedContactCommon ecc(paths, callId.at(i), uniqueId.at(i));
		record.update(ecc, sipContact.at(i), expire.at(i), q, cseq, updateTime.at(i), alias, acceptHeaders.at(i), false,
		              nullptr);
		const auto& contacts = record.getExtendedContacts();
		contacts.latest()->get()->mUserAgent = userAgent.at(i);
	}
}

void parseValidContactWithMultipleDevices() {
	auto record = createRecord();
	auto recordRef = createRecord();
	string contact{};
	recordAndStrForContactWithMultipleDevices(recordRef, contact);

	RecordSerializerJson recordSerializer;
	BC_ASSERT_TRUE(recordSerializer.parse(contact, record));
	compareRecords(record, recordRef);
}

void parseAndSerialize() {
	auto validContact = createValidContact();
	auto record = createRecord();

	// Parse
	RecordSerializerJson recordSerializer;
	BC_ASSERT_TRUE(recordSerializer.parse(validContact, record));

	// Serialize
	string serializedContact{};
	BC_ASSERT_TRUE(recordSerializer.serialize(record, serializedContact, true));

	string expectedContact = json::parse(validContact).dump(1, '\t');
	BC_ASSERT_STRING_EQUAL(serializedContact.c_str(), expectedContact.c_str());
}

void serializeValidContactWithoutOptionalAttributes() {
	string sipContact = "sip:username@[ipv6:address:]:50614;transport=tls";
	list<string> path = {};
	list<string> acceptHeaders = {"application/sdp"};
	string callId = "callId";
	string uniqueId = "<urn:uuid:unique-id>";
	time_t expire = kExpiresAt;
	time_t update = 1767973510;

	// Record without path nor user agent
	auto record = createRecord();
	ExtendedContactCommon ecc(path, callId, uniqueId);
	record.update(ecc, sipContact.c_str(), expire, 1.0, 21, update, false, acceptHeaders, false, nullptr);
	RecordSerializerJson recordSerializer;
	string serializedContact{};
	BC_ASSERT_TRUE(recordSerializer.serialize(record, serializedContact, true));

	auto validContact = createValidContact();
	auto jsonValidContact = json::parse(validContact);
	jsonValidContact["contacts"][0]["path"] = path;
	jsonValidContact["contacts"][0]["user-agent"] = "";
	string contactSerialized = json::parse(serializedContact).dump(1, '\t');
	string contactRef = jsonValidContact.dump(1, '\t');
	BC_ASSERT_STRING_EQUAL(contactSerialized.c_str(), contactRef.c_str());
}

void serializeValidContactWithMultipleDevices() {
	auto record = createRecord();
	string contactRef{};
	recordAndStrForContactWithMultipleDevices(record, contactRef);

	RecordSerializerJson recordSerializer;
	string serializedContact{};
	BC_ASSERT_TRUE(recordSerializer.serialize(record, serializedContact, true));
	string contactSerialized = json::parse(serializedContact).dump(1, '\t');
	BC_ASSERT_STRING_EQUAL(contactSerialized.c_str(), contactRef.c_str());
}

TestSuite _{
    "RecordSerializerJson",
    {
        CLASSY_TEST(parseValidContact),
        CLASSY_TEST(parseInvalidContact),
        CLASSY_TEST(parseValidContactWithMultipleDevices),
        CLASSY_TEST(parseAndSerialize),
        CLASSY_TEST(serializeValidContactWithoutOptionalAttributes),
        CLASSY_TEST(serializeValidContactWithMultipleDevices),
    },
};

} // namespace
} // namespace flexisip::tester