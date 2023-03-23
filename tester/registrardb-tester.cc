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

#include <cstring>
#include <sstream>
#include <string>

#include "bctoolbox/tester.h"

#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"

#include "module-pushnotification.hh"
#include "pushnotification/firebase/firebase-client.hh"
#include "utils/asserts.hh"
#include "utils/override-static.hh"
#include "utils/redis-sync-access.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {

class SuccessfulBindListener : public ContactUpdateListener {
public:
	std::shared_ptr<Record> mRecord{nullptr};

	virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
		mRecord = r;
	}
	void onError() override {
		BC_FAIL("This test doesn't expect an error response");
	}
	void onInvalid() override {
		BC_FAIL("This test doesn't expect an invalid response");
	}
	void onContactUpdated(const shared_ptr<ExtendedContact>&) override {
		BC_FAIL("This test doesn't expect a contact to be updated");
	}
};

class IgnoreUpdatesListener : public SuccessfulBindListener {
	void onContactUpdated(const shared_ptr<ExtendedContact>&) override {
	}
};

// Base class for testing UNSUBSCRIBE/SUBSCRIBE scenario.
// That tests that the subscription is still on if subscribe() methods
// is immediately called after unsubscribe(). We found out that with some
// backend (e.g. Redis) that may lead to a race condition that caused the subscription
// to be off.
template <typename TDatabase>
class SubsequentUnsubscribeSubscribeTest : public RegistrarDbTest<TDatabase> {
protected:
	// Protected types
	struct RegistrarStats : public ContactRegisteredListener {
		void onContactRegistered(const std::shared_ptr<Record>&, const std::string&) override {
			++onContactRegisteredCount;
		}

		int onContactRegisteredCount{0};
	};

	// Protected methods
	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();

		auto stats = make_shared<RegistrarStats>();

		const string topic{"user@sip.example.org"};
		const string uuid{"dummy-uuid"};
		SLOGD << "Subscribing to '" << topic << "'";
		regDb->subscribe(topic, stats);
		this->waitFor(1s);

		SLOGD << "Notifying topic[" << topic << "] with uuid[" << uuid << "]";
		regDb->publish(topic, uuid);
		BC_ASSERT_TRUE(this->waitFor([&stats]() { return stats->onContactRegisteredCount >= 1; }, 1s));
		BC_ASSERT_EQUAL(stats->onContactRegisteredCount, 1, int, "%d");

		SLOGD << "Subsequent Redis UNSUBSCRIBE/SUBSCRIBE";
		regDb->unsubscribe(topic, stats);
		regDb->subscribe(topic, stats);
		this->waitFor(1s);

		SLOGD << "Secondly Notifying topic[" << topic << "] with uuid[" << uuid << "]";
		regDb->publish(topic, uuid);
		BC_ASSERT_TRUE(this->waitFor([&stats]() { return stats->onContactRegisteredCount >= 2; }, 1s));
		BC_ASSERT_EQUAL(stats->onContactRegisteredCount, 2, int, "%d");
	}
};

/**
 * Returns contacts with push params that have passed `threshold` of their expiration
 */
template <typename TDatabase>
class TestFetchExpiringContacts : public RegistrarDbTest<TDatabase> {
	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();
		ContactInserter inserter(*regDb, *this->mAgent);
		auto threshold = 20.0 / 100.0;
		auto targetTimestamp = getCurrentTime() + 21;
		inserter.insert("sip:expected1@te.st;pn-provider=fake", 100s);
		inserter.insert("sip:expired@te.st;pn-provider=fake", 10s);
		inserter.insert("sip:expected2@te.st;pn-type=fake", 90s);
		inserter.insert("sip:unexpected@te.st;pn-provider=fake", 110s);
		inserter.insert("sip:unnotifiable@te.st", 100s);
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));

		// Cold loading script
		auto expiringContacts = std::vector<ExtendedContact>();
		regDb->fetchExpiringContacts(targetTimestamp, threshold, [&expiringContacts](auto&& returnedContacts) {
			expiringContacts = std::move(returnedContacts);
		});

		BC_ASSERT_TRUE(this->waitFor([&expiringContacts] { return !expiringContacts.empty(); }, 1s));
		BC_ASSERT_CPP_EQUAL(expiringContacts.size(), 2);
		std::unordered_set<std::string> expectedContactStrings = {"expected1", "expected2"};
		for (const auto& contact : expiringContacts) {
			auto contactString = contact.mSipContact->m_url->url_user;
			auto found = expectedContactStrings.erase(contactString);
			bc_assert(__FILE__, __LINE__, found == 1, ("unexpected contact returned: "s + contactString).c_str());
		}
		// Assert all expected contacts have been returned
		BC_ASSERT_EQUAL(expectedContactStrings.size(), 0, size_t, "%ld");

		// Script should be hot
		expiringContacts.clear();
		regDb->fetchExpiringContacts(targetTimestamp, threshold, [&expiringContacts](auto&& returnedContacts) {
			expiringContacts = std::move(returnedContacts);
		});

		BC_ASSERT_TRUE(this->waitFor([&expiringContacts] { return !expiringContacts.empty(); }, 1s));
		BC_ASSERT_CPP_EQUAL(expiringContacts.size(), 2);
	}
};

template <typename TDatabase>
class MaxContactsByAorIsHonored : public RegistrarDbTest<TDatabase> {
	void testExec() noexcept override {
		auto& uidFields = Record::sLineFieldNames;
		if (uidFields.empty()) uidFields = {"+sip.instance"}; // Do not rely on side-effects from other tests...
		auto maxContacts = overrideStaticVariable(Record::sMaxContacts, 3);
		auto* regDb = RegistrarDb::get();
		ContactInserter inserter(*regDb, *this->mAgent);
		const auto aor = "sip:morethan3@example.org";
		const auto expire = 87s;
		inserter.insert(aor, expire, "sip:existing1@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));
		inserter.insert(aor, expire, "sip:existing2@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));
		inserter.insert(aor, expire, "sip:existing3@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));

		inserter.insert(aor, expire, "sip:onetoomany@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));

		auto listener = make_shared<SuccessfulBindListener>();
		regDb->fetch(SipUri(aor), listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 3, int, "%d");
		}

		maxContacts = 5;
		inserter.insert(aor, expire, "sip:added4@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));
		inserter.insert(aor, expire, "sip:added5@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));

		listener->mRecord.reset();
		regDb->fetch(SipUri(aor), listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 5, int, "%d");
		}

		maxContacts = 2;
		inserter.insert(aor, expire, "sip:triggerupdate@example.org");
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));

		listener->mRecord.reset();
		regDb->fetch(SipUri(aor), listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 2, int, "%d");
		}
	}
};

class ContactsAreCorrectlyUpdatedWhenMatchedOnUri : public RegistrarDbTest<DbImplementation::Redis> {
	void testExec() noexcept override {
		auto _ = overrideStaticVariable(Record::sMaxContacts, 2);
		auto* regDb = RegistrarDb::get();
		sofiasip::Home home{};
		const auto contactBase = ":update-test@example.org";
		const auto contactStr = "sip"s + contactBase;
		const auto contact =
		    sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(contactStr.c_str()), nullptr);
		const SipUri aor(contactStr);
		BindingParameters params{};
		params.globalExpire = 96;
		params.callId = "insert";
		const auto listener = make_shared<IgnoreUpdatesListener>();
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		listener->mRecord = nullptr;
		params.callId = "update";
		const auto newContact = sip_contact_create(
		    home.home(), reinterpret_cast<const url_string_t*>((contactStr + ";new=param").c_str()), nullptr);
		regDb->bind(aor, newContact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		RedisSyncContext ctx = redisConnect("127.0.0.1", this->dbImpl.mPort);
		auto reply = ctx.command("HGETALL fs%s", contactBase);
		BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
		BC_ASSERT_EQUAL(reply->elements, 2, int, "%i");
		BC_ASSERT_EQUAL(reply->element[0]->type, REDIS_REPLY_STRING, int, "%i");
		BC_ASSERT_TRUE(StringUtils::startsWith(reply->element[0]->str, "fs-gen-"));
		BC_ASSERT_EQUAL(reply->element[1]->type, REDIS_REPLY_STRING, int, "%i");
		std::string serializedContact = reply->element[1]->str;
		BC_ASSERT_TRUE(serializedContact.find("new=param") != std::string::npos);

		// Force inject duplicated contacts inside Redis
		const auto prefix = [&serializedContact] {
			const char instanceParam[] = "callid=";
			return serializedContact.substr(0, serializedContact.find(instanceParam) + sizeof(instanceParam) - 1);
		}();
		const auto suffix = serializedContact.substr(prefix.size() + sizeof("insert") - 1);

		std::ostringstream cmd{};
		cmd << "HMSET fs" << contactBase;
		for (const auto& uid : {"duped1", "duped2", "duped3"}) {
			// Prefixing with `fs-gen-` otherwise the registrar will think it's an instance-id
			cmd << " fs-gen-" << uid << " " << prefix << uid << suffix;
		}

		auto insert = ctx.command(cmd.str().c_str());
		BC_ASSERT_EQUAL(insert->type, REDIS_REPLY_STATUS, int, "%i");
		BC_ASSERT_STRING_EQUAL(insert->str, "OK");

		listener->mRecord.reset();
		regDb->fetch(aor, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, int, "%d");
			SLOGD << *listener->mRecord;
		}

		// They are all the same contact, there can be only one
		listener->mRecord.reset();
		params.callId = "trigger-max-aor";
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, int, "%d");
		}

		{
			auto reply = ctx.command("HGETALL fs%s", contactBase);
			BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
			BC_ASSERT_EQUAL(reply->elements, 2, int, "%i");
		}
	}
};

class RegistrarTester : public RegistrarDbTest<DbImplementation::Redis> {

protected:
	// Protected methods
	void testExec() noexcept override {
		sofiasip::Home home;
		auto* regDb = RegistrarDb::get();
		auto listener = make_shared<IgnoreUpdatesListener>();

		SipUri from("sip:bob@example.org");
		BindingParameters params;
		params.globalExpire = 5;
		params.callId = "bob";
		params.cSeq = 0;

		sip_contact_t* ct;

		auto bind = [regDb, &from, &ct, &params, &listener, this, home = home.home()](auto contact, auto... args) {
			listener->mRecord.reset();
			ct = sip_contact_create(home, (url_string_t*)contact, args..., nullptr);
			regDb->bind(from, ct, params, listener);
			params.cSeq++;
			return waitFor([listener]() { return listener->mRecord != nullptr; }, 1s);
		};

		// Make sure the record inserted in the DB is what was intended
		auto checkFetch = [regDb, &listener, this]() {
			const auto recordAfterBind = listener->mRecord;
			listener->mRecord.reset();
			regDb->fetch(recordAfterBind->getAor(), listener);
			FAIL_IF(!waitFor([listener]() { return listener->mRecord != nullptr; }, 1s));
			const auto fetched = listener->mRecord;
			if (fetched && !fetched->isSame(*recordAfterBind)) {
				const auto& fetchedContacts = fetched->getExtendedContacts();
				BC_ASSERT_EQUAL(fetchedContacts.size(), recordAfterBind->getExtendedContacts().size(), size_t, "%zx");

				return ASSERTION_FAILED(
				    "Record obtained after fetch operation is NOT the same as after the initial bind()");
			}
			return ASSERTION_PASSED();
		};

		/* Add a simple contact */
		BC_ASSERT_TRUE(bind("sip:bob@192.168.0.2;transport=tcp"));
		if (listener->mRecord) {
			BC_ASSERT_EQUAL(listener->mRecord->getExtendedContacts().size(), 1, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Remove this contact with an expire parameter */
		BC_ASSERT_TRUE(bind("sip:bob@192.168.0.2;transport=tcp", "expires=0"));
		if (listener->mRecord) {
			BC_ASSERT_EQUAL(listener->mRecord->getExtendedContacts().size(), 0, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Add a simple contact */
		from = SipUri("sip:bobby@example.net");
		params.callId = "bobby";
		BC_ASSERT_TRUE(bind("sip:bobby@192.168.0.2;transport=tcp"));
		if (listener->mRecord) {
			BC_ASSERT_EQUAL(listener->mRecord->getExtendedContacts().size(), 1, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Update this contact based on URI comparison rules */
		BC_ASSERT_TRUE(bind("sip:bobby@192.168.0.2;transport=tcp;new-param=added"));
		if (listener->mRecord) {
			const auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL((*contacts.latest())->mSipContact->m_url->url_params,
			                       "transport=tcp;new-param=added");
			ASSERT_PASSED(checkFetch());
		}

		/* Add secondary contact */
		BC_ASSERT_TRUE(bind("sip:alias@192.168.0.2;transport=tcp"));
		if (listener->mRecord) {
			const auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 2, size_t, "%zx");
			const auto& latest = *contacts.latest();
			BC_ASSERT_STRING_EQUAL(latest->mSipContact->m_url->url_user, "alias");
			BC_ASSERT_STRING_EQUAL(latest->mSipContact->m_url->url_params,
			                       "transport=tcp"); // No new-param
			ASSERT_PASSED(checkFetch());
		}

		/* Remove these contacts with an expire parameter but with a different call-id */
		params.callId = "not-bobby";
		BC_ASSERT_TRUE(bind("sip:bobby@192.168.0.2;transport=tcp;debug-tag=delete", "expires=0"));
		if (listener->mRecord) {
			BC_ASSERT_EQUAL(listener->mRecord->getExtendedContacts().size(), 1, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		BC_ASSERT_TRUE(bind("sip:alias@192.168.0.2;transport=tcp", "expires=0"));
		if (listener->mRecord) {
			BC_ASSERT_EQUAL(listener->mRecord->getExtendedContacts().size(), 0, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Add a contact with a unique id */
		from = SipUri("sip:alice@example.net");
		params.callId = "alice";
		BC_ASSERT_TRUE(bind("sip:alice@10.0.0.2;transport=tcp", "+sip.instance=\"<urn::uuid::abcd>\""));
		if (listener->mRecord) {
			const auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL((*contacts.latest())->mKey.str().c_str(), "\"<urn::uuid::abcd>\"");
			ASSERT_PASSED(checkFetch());
		}

		/* Update this contact based on uuid */
		BC_ASSERT_TRUE(bind("sip:alice@10.0.0.3;transport=tcp", "+sip.instance=\"<urn::uuid::abcd>\""));
		if (listener->mRecord) {
			const auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL((*contacts.latest())->mSipContact->m_url->url_host, "10.0.0.3");
			ASSERT_PASSED(checkFetch());
		}
	}
};

class InstanceIDFeatureParamIsSerializedToRedis : public RegistrarDbTest<DbImplementation::Redis> {
	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();
		sofiasip::Home home{};
		const auto contactBase = ":instance-id-test@example.org";
		const auto contactStr = "sip"s + contactBase;
		const auto instanceIdFeatureParam = R"(+sip.instance="<instance-id-value>")";
		auto contact = sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(contactStr.c_str()),
		                                  instanceIdFeatureParam, nullptr);
		const SipUri aor(contactStr);
		BindingParameters params{};
		params.globalExpire = 231;
		params.callId = "instance-id-test";
		const auto listener = make_shared<SuccessfulBindListener>();
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		RedisSyncContext redis = redisConnect("127.0.0.1", this->dbImpl.mPort);
		const auto reply = redis.command("HGETALL fs%s", contactBase);
		BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
		BC_ASSERT_EQUAL(reply->elements, 2, int, "%i");
		BC_ASSERT_EQUAL(reply->element[0]->type, REDIS_REPLY_STRING, int, "%i");
		// The instance-id is used as key
		BC_ASSERT_STRING_EQUAL(reply->element[0]->str, R"("<instance-id-value>")");
		BC_ASSERT_EQUAL(reply->element[1]->type, REDIS_REPLY_STRING, int, "%i");
		// And is also serialized as part of the contact
		BC_ASSERT_PTR_NOT_NULL(std::strstr(reply->element[1]->str, instanceIdFeatureParam));
		SLOGD << "serializedContact: " << reply->element[1]->str;
	}
};

/**
 * Flexisip versions <2.3.0 use the Call-ID as the contact key within the Record hash in Redis.
 * When loading contacts inserted by such versions from Redis, the current implementation will assume they are indexed
 * by some kind of unique id (since Call-IDs do not start with the "fs-gen-" placeholder flag prefix) and skip any check
 * based on the URI matching rules. Even if the exact contact is registered again, it will NOT match the existing entry
 * which will simply be kept until it either expires or is pushed out by the maxAOR limit.
 */
class CallIDsPreviouslyUsedAsKeysAreInterpretedAsUniqueIDs : public RegistrarDbTest<DbImplementation::Redis> {
	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();
		sofiasip::Home home{};
		const auto callId = "ZwPAMpQSC9"; // Can be anything as long as it does not start with `fs-gen-`
		const auto contactBase = ":migration-test@example.org";
		const auto contactStr = "sip"s + contactBase;
		auto contact =
		    sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(contactStr.c_str()), nullptr);
		const SipUri aor(contactStr);
		BindingParameters params{};
		params.globalExpire = 231;
		params.callId = callId;
		const auto listener = make_shared<SuccessfulBindListener>();
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		const auto& contactKey = (*listener->mRecord->getExtendedContacts().latest())->mKey.str();
		RedisSyncContext redis = redisConnect("127.0.0.1", this->dbImpl.mPort);
		const auto serializedContact = redis.command("HGET fs%s %s", contactBase, contactKey.c_str());
		BC_ASSERT_EQUAL(serializedContact->type, REDIS_REPLY_STRING, int, "%i");
		// Fake a Call-ID indexed entry by replacing the inserted entry
		{
			const auto status = redis.command("HSET fs%s %s %s", contactBase, callId, serializedContact->str);
			BC_ASSERT_EQUAL(status->type, REDIS_REPLY_INTEGER, int, "%i");
			BC_ASSERT_EQUAL(status->integer, 1, int, "%i");
		}
		{
			const auto status = redis.command("HDEL fs%s %s", contactBase, contactKey.c_str());
			BC_ASSERT_EQUAL(status->type, REDIS_REPLY_INTEGER, int, "%i");
			BC_ASSERT_EQUAL(status->integer, 1, int, "%i");
		}

		listener->mRecord.reset();
		params.callId = "attempted-update";
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		{
			auto reply = redis.command("HGETALL fs%s", contactBase);
			BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
			BC_ASSERT_EQUAL(reply->elements, 4, int, "%i");
			BC_ASSERT_EQUAL(reply->element[0]->type, REDIS_REPLY_STRING, int, "%i");
			BC_ASSERT_EQUAL(reply->element[2]->type, REDIS_REPLY_STRING, int, "%i");
			std::unordered_set<std::string> keys{reply->element[0]->str, reply->element[2]->str};
			BC_ASSERT_TRUE(keys.find(callId) != keys.end());
		}
	}
};

class ExpiredContactsArePurgedFromRedis : public RegistrarDbTest<DbImplementation::Redis> {
	void testExec() override {
		auto* regDb = RegistrarDb::get();
		sofiasip::Home home{};
		const auto contactBase = ":expiration-test@example.org";
		const auto contactStr = "sip"s + contactBase;
		auto contact =
		    sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(contactStr.c_str()), nullptr);
		const SipUri aor(contactStr);
		BindingParameters params{};
		params.globalExpire = 239;
		params.callId = "expiration-test";
		const auto listener = make_shared<SuccessfulBindListener>();
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		RedisSyncContext redis = redisConnect("127.0.0.1", this->dbImpl.mPort);
		auto reply = redis.command("HGETALL fs%s", contactBase);
		BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
		BC_ASSERT_EQUAL(reply->elements, 2, int, "%i");
		BC_ASSERT_EQUAL(reply->element[0]->type, REDIS_REPLY_STRING, int, "%i");
		const auto contactKey = reply->element[0]->str;
		BC_ASSERT_EQUAL(reply->element[1]->type, REDIS_REPLY_STRING, int, "%i");
		char* serializedContact = reply->element[1]->str;
		BC_ASSERT_PTR_NULL(std::strstr(
		    serializedContact, contactKey)); // The key is auto generated and is not serialized as part of the contact
		SLOGD << "serializedContact: " << serializedContact;

		// Mangle contact update timestamp inside Redis
		const char param[] = "updatedAt=";
		char* index = std::strstr(serializedContact, param) + sizeof(param);
		BC_ASSERT_PTR_NOT_NULL(index);
		index[0] = '0'; // Rewinding at least 31 years back, that should expire it

		auto insert = redis.command("HMSET fs%s %s %s", contactBase, contactKey, serializedContact);
		BC_ASSERT_EQUAL(insert->type, REDIS_REPLY_STATUS, int, "%i");
		BC_ASSERT_STRING_EQUAL(insert->str, "OK");

		listener->mRecord.reset();
		regDb->fetch(aor, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 0, int, "%d");
		}

		listener->mRecord.reset();
		params.callId = "trigger-cleanup";
		contact = sip_contact_create(home.home(),
		                             reinterpret_cast<const url_string_t*>("sip:trigger-cleanup@example.org"), nullptr);
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		{
			auto& contacts = listener->mRecord->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, int, "%d");
		}

		{
			auto reply = redis.command("HGETALL fs%s", contactBase);
			BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
			BC_ASSERT_EQUAL(reply->elements, 2, int, "%i");
			BC_ASSERT_EQUAL(reply->element[1]->type, REDIS_REPLY_STRING, int, "%i");
			BC_ASSERT_PTR_NOT_NULL(std::strstr(reply->element[1]->str, "sip:trigger-cleanup@example.org"));
		}
	}
};

namespace {
TestSuite
    _("RegistrarDB",
      {
          CLASSY_TEST(InstanceIDFeatureParamIsSerializedToRedis),
          CLASSY_TEST(CallIDsPreviouslyUsedAsKeysAreInterpretedAsUniqueIDs),
          TEST_NO_TAG("Fetch expiring contacts on Redis", run<TestFetchExpiringContacts<DbImplementation::Redis>>),
          TEST_NO_TAG("Fetch expiring contacts in Internal DB",
                      run<TestFetchExpiringContacts<DbImplementation::Internal>>),
          TEST_NO_TAG("An AOR cannot contain more than max-contacts-by-aor [Internal]",
                      run<MaxContactsByAorIsHonored<DbImplementation::Internal>>),
          TEST_NO_TAG("An AOR cannot contain more than max-contacts-by-aor [Redis]",
                      run<MaxContactsByAorIsHonored<DbImplementation::Redis>>),
          TEST_NO_TAG("Contacts are correctly updated when matched on URI [Redis]",
                      run<ContactsAreCorrectlyUpdatedWhenMatchedOnUri>),
          TEST_NO_TAG("Expired contacts are purged from Redis", run<ExpiredContactsArePurgedFromRedis>),
          TEST_NO_TAG("Subsequent UNSUBSCRIBE/SUBSCRIBE with internal backend",
                      run<SubsequentUnsubscribeSubscribeTest<DbImplementation::Internal>>),
          TEST_NO_TAG("Subsequent UNSUBSCRIBE/SUBSCRIBE with Redis backend",
                      run<SubsequentUnsubscribeSubscribeTest<DbImplementation::Redis>>),
          TEST_NO_TAG("Registrations with Redis backend", run<RegistrarTester>),
      },
      Hooks().beforeSuite([]() noexcept {
	      const auto* seed = std::getenv("FLEXISEED");
	      if (seed) {
		      flexisip::ContactKey::sRsg.mEngine.seed(
		          std::stoll(seed)); // will throw (and abort) if seed is not an integer
	      }
	      return 0;
      }));
}
} // namespace tester
} // namespace flexisip
