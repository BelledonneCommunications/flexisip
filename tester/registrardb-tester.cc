/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <cstdlib>

#include "flexisip/configmanager.hh"
#include "flexisip/module-pushnotification.hh"
#include "flexisip/registrardb.hh"

#include "pushnotification/firebase/firebase-client.hh"

#include "utils/asserts.hh"
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
		void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) override {
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
		virtual void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
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

	// Protected methods
	void testExec() noexcept override {
		sofiasip::Home home;
		auto* regDb = RegistrarDb::get();
		std::shared_ptr<TestListener> listener = make_shared<TestListener>();

		SipUri from("sip:bob@example.org");
		BindingParameters params;
		params.globalExpire = 5;
		params.callId = "bob";

		sip_contact_t* ct;

		auto bind = [regDb, &from, &ct, &params, &listener, this, home = home.home()](auto contact, auto... args) {
			listener->reset();
			ct = sip_contact_create(home, (url_string_t*)contact, args..., nullptr);
			regDb->bind(from, ct, params, listener);
			return waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s);
		};

		// Make sure the record inserted in the DB is what was intended
		auto checkFetch = [regDb, &listener, this]() {
			const auto recordAfterBind = listener->getRecord();
			listener->reset();
			regDb->fetch(recordAfterBind->getAor(), listener);
			FAIL_IF(!waitFor([listener]() { return listener->getRecord() != nullptr; }, 1s));
			const auto fetched = listener->getRecord();
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
		if (listener->getRecord()) {
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 1, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Remove this contact with an expire parameter */
		BC_ASSERT_TRUE(bind("sip:bob@192.168.0.2;transport=tcp", "expires=0"));
		if (listener->getRecord()) {
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 0, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Add a simple contact */
		from = SipUri("sip:bobby@example.net");
		params.callId = "bobby";
		BC_ASSERT_TRUE(bind("sip:bobby@192.168.0.2;transport=tcp"));
		if (listener->getRecord()) {
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 1, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Update this contact based on URI comparison rules */
		BC_ASSERT_TRUE(bind("sip:bobby@192.168.0.2;transport=tcp;new-param=added"));
		if (listener->getRecord()) {
			const auto& contacts = listener->getRecord()->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL(contacts.front()->mSipContact->m_url->url_params, "transport=tcp;new-param=added");
			ASSERT_PASSED(checkFetch());
		}

		/* Add secondary contact */
		BC_ASSERT_TRUE(bind("sip:alias@192.168.0.2;transport=tcp"));
		if (listener->getRecord()) {
			const auto& contacts = listener->getRecord()->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 2, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL(contacts.back()->mSipContact->m_url->url_user, "alias");
			BC_ASSERT_STRING_EQUAL(contacts.back()->mSipContact->m_url->url_params, "transport=tcp"); // No new-param
			ASSERT_PASSED(checkFetch());
		}

		/* Remove these contacts with an expire parameter but with a different call-id */
		params.callId = "not-bobby";
		BC_ASSERT_TRUE(bind("sip:bobby@192.168.0.2;transport=tcp;debug-tag=delete", "expires=0"));
		if (listener->getRecord()) {
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 1, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		BC_ASSERT_TRUE(bind("sip:alias@192.168.0.2;transport=tcp", "expires=0"));
		if (listener->getRecord()) {
			BC_ASSERT_EQUAL(listener->getRecord()->getExtendedContacts().size(), 0, size_t, "%zx");
			ASSERT_PASSED(checkFetch());
		}

		/* Add a contact with a unique id */
		from = SipUri("sip:alice@example.net");
		params.callId = "alice";
		BC_ASSERT_TRUE(bind("sip:alice@10.0.0.2;transport=tcp", "+sip.instance=\"<urn::uuid::abcd>\""));
		if (listener->getRecord()) {
			const auto& contacts = listener->getRecord()->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL(contacts.front()->getUniqueId().c_str(), "\"<urn::uuid::abcd>\"");
			ASSERT_PASSED(checkFetch());
		}

		/* Update this contact based on uuid */
		BC_ASSERT_TRUE(bind("sip:alice@10.0.0.3;transport=tcp", "+sip.instance=\"<urn::uuid::abcd>\""));
		if (listener->getRecord()) {
			const auto& contacts = listener->getRecord()->getExtendedContacts();
			BC_ASSERT_EQUAL(contacts.size(), 1, size_t, "%zx");
			BC_ASSERT_STRING_EQUAL(contacts.front()->mSipContact->m_url->url_host, "10.0.0.3");
			ASSERT_PASSED(checkFetch());
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
      },
      Hooks().beforeSuite([]() noexcept {
	      const auto* seed = std::getenv("FLEXISEED");
	      if (seed) {
		      flexisip::InstanceID::sRsg.mEngine.seed(
		          std::stoll(seed)); // will throw (and abort) if seed is not an integer
	      }
	      return 0;
      }));
}
} // namespace tester
} // namespace flexisip
