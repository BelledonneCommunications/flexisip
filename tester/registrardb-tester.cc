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

#include "compat/hiredis/hiredis.h"

#include "flexisip/configmanager.hh"

#include "module-pushnotification.hh"
#include "utils/redis-sync-access.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-suite.hh"

using namespace std;
namespace pn = flexisip::pushnotification;

namespace flexisip {
namespace tester {

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
		void onContactRegistered([[maybe_unused]] const std::shared_ptr<Record>& r, [[maybe_unused]] const std::string& uid) override {
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
 * Should return contacts expiring within [startTimestamp ; startTimestamp + timeRange[
 */
template <typename TDatabase>
class TestFetchExpiringContacts : public RegistrarDbTest<TDatabase> {
	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();
		auto inserter = ContactInserter(*regDb, *this->mAgent);
		inserter.insert("sip:expected1@te.st", 1s);
		inserter.insert("sip:unexpected@te.st", 3s);
		inserter.insert("sip:expected2@te.st", 2s);
		BC_ASSERT_TRUE(this->waitFor([&inserter] { return inserter.finished(); }, 1s));
		auto targetTimestamp = getCurrentTime() + 1;
		auto timeRange = 2s;

		// Cold loading script
		auto expiringContacts = std::vector<ExtendedContact>();
		regDb->fetchExpiringContacts(targetTimestamp, timeRange, [&expiringContacts](auto&& returnedContacts) {
			expiringContacts = std::move(returnedContacts);
		});

		BC_ASSERT_TRUE(this->waitFor([&expiringContacts] { return !expiringContacts.empty(); }, 1s));
		BC_ASSERT_TRUE(expiringContacts.size() == 2);
		std::unordered_set<std::string> expectedContactStrings = {"sip:expected1@te.st", "sip:expected2@te.st"};
		for (const auto& contact : expiringContacts) {
			// Fail if the returned contact is not in the expected strings
			BC_ASSERT_TRUE(expectedContactStrings.erase(ExtendedContact::urlToString(contact.mSipContact->m_url)) == 1);
		}
		// Assert all expected contacts have been returned
		BC_ASSERT_TRUE(expectedContactStrings.empty());

		// Script should be hot
		expiringContacts.clear();
		regDb->fetchExpiringContacts(targetTimestamp, timeRange, [&expiringContacts](auto&& returnedContacts) {
			expiringContacts = std::move(returnedContacts);
		});

		BC_ASSERT_TRUE(this->waitFor([&expiringContacts] { return !expiringContacts.empty(); }, 1s));
		BC_ASSERT_TRUE(expiringContacts.size() == 2);
		expectedContactStrings = {"sip:expected1@te.st", "sip:expected2@te.st"};
		for (const auto& contact : expiringContacts) {
			// Fail if the returned contact is not in the expected strings
			BC_ASSERT_TRUE(expectedContactStrings.erase(ExtendedContact::urlToString(contact.mSipContact->m_url)) == 1);
		}
		// Assert all expected contacts have been returned
		BC_ASSERT_TRUE(expectedContactStrings.empty());
	}
};

template <typename TDatabase>
class MaxContactsByAorIsHonored : public RegistrarDbTest<TDatabase> {
	class TestListener : public ContactUpdateListener {
	public:
		std::shared_ptr<Record> mRecord{nullptr};

		virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
			mRecord = r;
		}
		virtual void onError() override {
		}
		virtual void onInvalid() override {
		}
		virtual void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		}
	};

	void testExec() noexcept override {
		auto previous = Record::sMaxContacts;
		Record::sMaxContacts = 3;
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

		auto listener = make_shared<TestListener>();
		regDb->fetch(SipUri(aor), listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));
		auto& contacts = listener->mRecord->getExtendedContacts();
		BC_ASSERT_EQUAL(contacts.size(), 3, int, "%d");
		Record::sMaxContacts = previous;
	}
};

class SameUriButDifferentCallIdInsertsANewContact : public RegistrarDbTest<DbImplementation::Redis> {
	class TestListener : public ContactUpdateListener {
	public:
		std::shared_ptr<Record> mRecord{nullptr};

		virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
			mRecord = r;
		}
		virtual void onError() override {
		}
		virtual void onInvalid() override {
		}
		virtual void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		}
	};

	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();
		sofiasip::Home home{};
		const auto contactBase = ":update-test@example.org";
		const auto contactStr = "sip"s + contactBase;
		const auto contact =
		    sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(contactStr.c_str()), nullptr);
		const SipUri aor(contactStr);
		BindingParameters params{};
		params.globalExpire = 96;
		params.callId = "insert-1";
		const auto listener = make_shared<TestListener>();
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		listener->mRecord = nullptr;
		params.callId = "insert-2";
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		auto* ctx = redisConnect("127.0.0.1", this->dbImpl.mPort);
		BC_ASSERT_TRUE(ctx && !ctx->err);
		auto* reply = reinterpret_cast<redisReply*>(redisCommand(ctx, "HGETALL fs%s", contactBase));
		BC_ASSERT_PTR_NOT_NULL(reply);
		BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
		BC_ASSERT_EQUAL(reply->elements, 4, int, "%i");
		// The call-ids are used as keys
		BC_ASSERT_EQUAL(reply->element[0]->type, REDIS_REPLY_STRING, int, "%i");
		BC_ASSERT_TRUE(StringUtils::startsWith(reply->element[0]->str, "insert-"));
		BC_ASSERT_EQUAL(reply->element[2]->type, REDIS_REPLY_STRING, int, "%i");
		BC_ASSERT_TRUE(StringUtils::startsWith(reply->element[2]->str, "insert-"));
		freeReplyObject(reply);
		redisFree(ctx);
	}
};

class ContactsAreUpdatedBasedOnCallId : public RegistrarDbTest<DbImplementation::Redis> {
	class TestListener : public ContactUpdateListener {
	public:
		std::shared_ptr<Record> mRecord{nullptr};

		virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
			mRecord = r;
		}
		virtual void onError() override {
		}
		virtual void onInvalid() override {
		}
		virtual void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		}
	};

	void testExec() noexcept override {
		auto* regDb = RegistrarDb::get();
		sofiasip::Home home{};
		const auto contactBase = ":update-test@example.org";
		const auto contactStr = "sip"s + contactBase;
		const auto contact =
		    sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(contactStr.c_str()), nullptr);
		const SipUri aor(contactStr);
		BindingParameters params{};
		params.globalExpire = 2256;
		params.callId = "update-based-on-callid";
		const auto listener = make_shared<TestListener>();
		regDb->bind(aor, contact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		listener->mRecord = nullptr;
		const auto newContact = sip_contact_create(
		    home.home(), reinterpret_cast<const url_string_t*>("sip:completely-different@example.com"), nullptr);
		regDb->bind(aor, newContact, params, listener);
		BC_ASSERT_TRUE(this->waitFor([&record = listener->mRecord]() { return record != nullptr; }, 1s));

		auto* ctx = redisConnect("127.0.0.1", this->dbImpl.mPort);
		BC_ASSERT_TRUE(ctx && !ctx->err);
		auto* reply = reinterpret_cast<redisReply*>(redisCommand(ctx, "HGETALL fs%s", contactBase));
		BC_ASSERT_PTR_NOT_NULL(reply);
		BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
		BC_ASSERT_EQUAL(reply->elements, 2, int, "%i");
		BC_ASSERT_EQUAL(reply->element[0]->type, REDIS_REPLY_STRING, int, "%i");
		BC_ASSERT_STRING_EQUAL(reply->element[0]->str, "update-based-on-callid");
		BC_ASSERT_EQUAL(reply->element[1]->type, REDIS_REPLY_STRING, int, "%i");
		BC_ASSERT_TRUE(std::string(reply->element[1]->str).find("completely-different") != std::string::npos);
		freeReplyObject(reply);
		redisFree(ctx);
	}
};

class RegistrarTester : public RegistrarDbTest<DbImplementation::Redis> {

protected:
	class TestListener : public ContactUpdateListener {
	public:
		virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
			mRecord = r;
		}
		virtual void onError() override {
		}
		virtual void onInvalid() override {
		}
		virtual void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		}
		std::shared_ptr<Record> getRecord() const {
			return mRecord;
		}
		void reset() {
			mRecord.reset();
		}

	private:
		std::shared_ptr<Record> mRecord;
	};

	void checkFetch(const std::shared_ptr<Record>& recordAfterBind) {
		auto* regDb = RegistrarDb::get();
		std::shared_ptr<TestListener> listener = make_shared<TestListener>();
		/* Ensure that the Record obtained after fetch operation is the same as the one after the initial bind() */
		regDb->fetch(recordAfterBind->getAor(), listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			BC_ASSERT_TRUE(listener->getRecord()->isSame(*recordAfterBind));
		}
	}
	// Protected methods
	void testExec() noexcept override {
		sofiasip::Home home;
		auto* regDb = RegistrarDb::get();
		std::shared_ptr<TestListener> listener = make_shared<TestListener>();

		SipUri from("sip:bob@example.org");
		BindingParameters params;
		params.globalExpire = 4;
		params.callId = "xyz";

		sip_contact_t* ct;

		/* Add a simple contact */
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:bob@192.168.0.2;transport=tcp", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			BC_ASSERT_TRUE(listener->getRecord()->getExtendedContacts().size() == 1);
			checkFetch(listener->getRecord());
		}

		/* Remove this contact with an expire parameter */
		listener->reset();
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:bob@192.168.0.2;transport=tcp", "expires=0", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			BC_ASSERT_TRUE(listener->getRecord()->getExtendedContacts().size() == 0);
			checkFetch(listener->getRecord());
		}

		/* Add a simple contact */
		listener->reset();
		from = SipUri("sip:bobby@example.net");
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:bobby@192.168.0.2;transport=tcp", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			BC_ASSERT_TRUE(listener->getRecord()->getExtendedContacts().size() == 1);
			checkFetch(listener->getRecord());
		}
		
		/* Remove this contact with an expire parameter but with a different call-id */
		listener->reset();
		ct =
		    sip_contact_create(home.home(), (url_string_t*)"sip:bobby@192.168.0.2;transport=tcp", "expires=0", nullptr);
		params.callId = "abcdef";
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			BC_ASSERT_TRUE(listener->getRecord()->getExtendedContacts().size() == 0);
			checkFetch(listener->getRecord());
		}
		
		/* Add a contact with a unique id */
		from = SipUri("sip:alice@example.net");
		listener->reset();
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:alice@10.0.0.2;transport=tcp",
		                        "+sip.instance=\"<urn::uuid::abcd>\"", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			BC_ASSERT_TRUE( listener->getRecord()->getExtendedContacts().size() == 1);
			checkFetch(listener->getRecord());
		}

		/* Update this contact */
		listener->reset();
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:alice@10.0.0.3;transport=tcp",
		                        "+sip.instance=\"<urn::uuid::abcd>\"", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		if (listener->getRecord()) {
			if (BC_ASSERT_TRUE(listener->getRecord()->getExtendedContacts().size() == 1)) {
				BC_ASSERT_STRING_EQUAL(
				    listener->getRecord()->getExtendedContacts().front()->mSipContact->m_url->url_host, "10.0.0.3");
			}
			checkFetch(listener->getRecord());
		}
		/* let this Record expire, make sure that it is deleted */
		sleep(5);
		listener->reset();
		regDb->fetch(from, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		BC_ASSERT_TRUE(listener->getRecord() && listener->getRecord()->getExtendedContacts().size() == 0);

		/* bind a new Record with two contacts with diffent expirations */
		listener->reset();
		params.globalExpire = 6;
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:alice@10.0.0.3;transport=tcp",
		                        "+sip.instance=\"<urn::uuid::abcd>\"", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		listener->reset();
		params.callId = "wtf";
		ct = sip_contact_create(home.home(), (url_string_t*)"sip:alice@10.0.0.18;transport=tcp",
		                        "+sip.instance=\"<urn::uuid::efgh>\";expires=3", nullptr);
		regDb->bind(from, ct, params, listener);
		BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
		listener->reset();

		/* Checking that fetch() has 2 contacts. */
		regDb->fetch(from, listener);
		if (BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s))){
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 2, int, "%d");
		}
		sleep(4);
		listener->reset();
		/* One should have expired, checking if one is remaining. */
		regDb->fetch(from, listener);
		if (BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s))){
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 1, int, "%d");
		}
		sleep(3);
		cout << "Both should be expired now, checking that full record is cleared automatically by redis." << endl;

		/* We do this by doing a raw redis request because regDb->fetch() does cleaning of expired contacts.
		 * However, we really want to assert that redis automatically cleans fully expired Records, without
		 * RegistrarDb action. */
		RedisSyncContext redis = redisConnect("127.0.0.1", this->dbImpl.mPort);
		auto reply = redis.command("HGETALL fs:%s@%s", from.getUser().c_str(), from.getHost().c_str());
		BC_ASSERT_EQUAL(reply->type, REDIS_REPLY_ARRAY, int, "%i");
		BC_ASSERT_EQUAL(reply->elements, 0, int, "%i");

		/* Make a fetch to ensure as well */
		listener->reset();
		regDb->fetch(from, listener);
		if (BC_ASSERT_TRUE(waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s))){
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 0, int, "%d");
		}
	}
};

namespace {
TestSuite
    _("RegistrarDB",
      {
          TEST_NO_TAG("Fetch expiring contacts on Redis", run<TestFetchExpiringContacts<DbImplementation::Redis>>),
          TEST_NO_TAG("Fetch expiring contacts in Internal DB",
                      run<TestFetchExpiringContacts<DbImplementation::Internal>>),
          TEST_NO_TAG("Subsequent UNSUBSCRIBE/SUBSCRIBE with internal backend",
                      run<SubsequentUnsubscribeSubscribeTest<DbImplementation::Internal>>),
          TEST_NO_TAG("Subsequent UNSUBSCRIBE/SUBSCRIBE with Redis backend",
                      run<SubsequentUnsubscribeSubscribeTest<DbImplementation::Redis>>),
          TEST_NO_TAG("Registrations with Redis backend", run<RegistrarTester>),
      });
}
} // namespace tester
} // namespace flexisip
