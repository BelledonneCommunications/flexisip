/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <memory>
#include <optional>

#include <sys/resource.h>

#include "bctoolbox/tester.h"

#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"

#include "libhiredis-wrapper/redis-async-session.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "registrardb-redis.hh"
#include "utils/asserts.hh"
#include "utils/core-assert.hh"
#include "utils/override-static.hh"
#include "utils/redis-sync-access.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/successful-bind-listener.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std::chrono_literals;

namespace flexisip::tester::registrardb_redis {
namespace {

struct SuiteScope {
	RedisServer redis{};
	Server proxyServer{
	    {
	        {"module::Registrar/db-implementation", "redis"},
	        {"module::Registrar/redis-server-domain", "localhost"},
	        {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	        {"module::Registrar/redis-slave-check-period", "1" /* second */},
	    },
	};
	CoreAssert<> asserter{proxyServer};
};

std::optional<SuiteScope> SUITE_SCOPE;

class OperationFailedListener : public ContactUpdateListener {
public:
	bool finished = false;

	OperationFailedListener() {
	}

	void onRecordFound(const std::shared_ptr<Record>&) override {
		BC_HARD_FAIL("unexpected call to onRecordFound");
	}
	void onError(const SipStatus&) override {
		finished = true;
	}
	void onInvalid(const SipStatus&) override {
		BC_HARD_FAIL("unexpected call to onInvalid");
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
		BC_HARD_FAIL("unexpected call to onContactUpdated");
	}
};

class NullRecordListener : public ContactUpdateListener {
public:
	std::uint8_t callCount = 0;

	virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
		BC_ASSERT_PTR_NULL(r);
		++callCount;
	}
	void onError(const SipStatus&) override {
		BC_FAIL("This test doesn't expect an error response");
	}
	void onInvalid(const SipStatus&) override {
		BC_FAIL("This test doesn't expect an invalid response");
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
		BC_FAIL("This test doesn't expect a contact to be updated");
	}
};

class ContactRegisteredCallback : public ContactRegisteredListener {
public:
	template <typename TCallback>
	ContactRegisteredCallback(TCallback&& callback) : mCallback(std::forward<TCallback>(callback)) {
	}

private:
	void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) override {
		mCallback(r, uid);
	}

	std::function<void(const std::shared_ptr<Record>&, const std::string&)> mCallback;
};

class SuccessfulConnectionListener : public RegistrarDbStateListener {
public:
	bool successful = false;
	bool called = false;

private:
	void onRegistrarDbWritable(bool writable) override {
		called = true;
		successful = writable;
	}
};

void mContext_should_be_checked_on_serializeAndSendToRedis() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const auto* backend = dynamic_cast<const RegistrarDbRedisAsync*>(&registrar.getRegistrarBackend());
	BC_HARD_ASSERT(backend != nullptr);
	auto& registrarBackend = const_cast<RegistrarDbRedisAsync&>(*backend); // we want to force a behavior

	const auto placeholder = "sip:placeholder@example.org";
	BindingParameters bindParams;
	bindParams.globalExpire = 3001;
	bindParams.callId = __FUNCTION__;
	sofiasip::Home home{};
	auto listener = std::make_shared<OperationFailedListener>();

	registrar.bind(SipUri(placeholder), sip_contact_make(home.home(), placeholder), bindParams, listener);

	// disconnecting before the previous bind operation finishes
	RegistrarDbRedisAsync::forceDisconnectForTest(registrarBackend);

	// The bind() ends in error, but there should be no segfault
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(30, [&finished = listener->finished] { return finished; }));
}

void auto_connect_on_command() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const auto* backend = dynamic_cast<const RegistrarDbRedisAsync*>(&registrar.getRegistrarBackend());
	BC_HARD_ASSERT(backend != nullptr);
	auto& registrarBackend = const_cast<RegistrarDbRedisAsync&>(*backend); // we want to force a behavior

	RegistrarDbRedisAsync::forceDisconnectForTest(registrarBackend);
	BC_HARD_ASSERT(!registrar.isWritable());

	registrar.fetch(SipUri("sip:redis-auto-connect@example.org"), nullptr);

	// Automatically reconnected to call the command
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&registrar] { return registrar.isWritable(); }));
}

void bindRetryOnBrokenConnection() {
	StaticOverride _{RegistrarDbRedisAsync::bindRetryTimeout, 20ms};
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	auto registrarBackend = dynamic_cast<const RegistrarDbRedisAsync*>(&registrar.getRegistrarBackend());
	BC_HARD_ASSERT(registrarBackend != nullptr);

	const auto aor = "sip:bind-retry@example.org";
	BindingParameters bindParams;
	bindParams.globalExpire = 3125;
	bindParams.callId = __FUNCTION__;
	sofiasip::Home home{};
	auto listener = std::make_shared<SuccessfulBindListener>();
	redis::async::SubscriptionSession keyMissListener{};
	keyMissListener.connect(SUITE_SCOPE->proxyServer.getRoot()->getCPtr(), "localhost", SUITE_SCOPE->redis.port());
	bool keyFetched = false;
	bool subscribed = false;
	{
		auto* keymissReady = keyMissListener.tryGetState<decltype(keyMissListener)::Ready>();
		BC_HARD_ASSERT(keymissReady != nullptr);
		// https://redis.io/docs/manual/keyspace-notifications/
		// Set up keymiss event notifications
		RedisSyncContext ctx = redisConnect("localhost", SUITE_SCOPE->redis.port());
		auto reply = ctx.command("CONFIG SET notify-keyspace-events Em");
		// TODO Remove when dropping support for Redis < 6.0 (Rocky8)
		if (reply->type == REDIS_REPLY_ERROR) {
			SLOGE << "tester: ABORTING TEST:\n"
			         "This Redis server does not support listening for keymiss events. "
			         "This test is irrelevant and unstable, and would disturb the following tests in the suite";
			return;

		} else {
			BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
			BC_ASSERT_STRING_EQUAL(reply->str, "OK");
		}

		keymissReady->subscriptions()["__keyevent@0__:keymiss"].subscribe([&keyFetched, &subscribed](auto, auto reply) {
			const auto array = EXPECT_VARIANT(redis::reply::Array).in(std::move(reply));
			const auto type = EXPECT_VARIANT(redis::reply::String).in(array[0]);
			if (type == "subscribe") {
				subscribed = true;
				return;
			}
			if (type != "message") return;
			const auto payload = EXPECT_VARIANT(redis::reply::String).in(array[2]);
			if (payload != "fs:bind-retry@example.org") return;
			keyFetched = true;
		});
	}
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&subscribed] { return subscribed; }));

	registrar.bind(SipUri(aor), sip_contact_make(home.home(), aor), bindParams, listener);
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&keyFetched] { return keyFetched; }));
	// Break connection
	SUITE_SCOPE->redis.restart();

	// Let the Registrar notice
	BC_ASSERT_TRUE(
	    SUITE_SCOPE->asserter.iterateUpTo(10, [&registrarBackend] { return !registrarBackend->isConnected(); }));
	// Wait for the server to be up again
	SUITE_SCOPE->redis.port();
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(10, [&record = listener->mRecord] { return record != nullptr; }));
}

void subscribeToKeyExpiration() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const Record::Key topic{SipUri("sip:expiring-key@example.org"), registrar.useGlobalDomain()};
	std::optional<Record::Key> actualTopic{};
	const auto listener = std::make_shared<ContactRegisteredCallback>(
	    [&actualTopic](const std::shared_ptr<Record>& record, const auto& userId) {
		    BC_ASSERT_CPP_EQUAL(userId, "");
		    BC_HARD_ASSERT(record != nullptr);
		    actualTopic = record->getKey();
	    });
	RedisSyncContext ctx = redisConnect("localhost", SUITE_SCOPE->redis.port());
	{
		// https://redis.io/docs/manual/keyspace-notifications/
		// Set up key expired event notifications
		const auto reply = ctx.command("CONFIG SET notify-keyspace-events Ex");
		BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
		BC_ASSERT_STRING_EQUAL(reply->str, "OK");
	}
	registrar.subscribe(topic, listener);
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(
	    10,
	    [&registrar, &topic] {
		    const auto& registrarBackend = dynamic_cast<const RegistrarDbRedisAsync&>(registrar.getRegistrarBackend());
		    const auto* subSession = registrarBackend.getRedisClient().getSubSessionIfReady();
		    if (!subSession) return false;
		    auto subscriptions = subSession->subscriptions();
		    if (subscriptions.size() == 0) return false;

		    const auto entry = subscriptions[topic.asString()];
		    return entry.subscribed() && !entry.isFresh();
	    },
	    50ms));

	// SET a key expiring in 20ms
	const auto reply = ctx.command("SET %s 'stub-payload' PX 20", topic.toRedisKey().c_str());
	BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
	BC_ASSERT_STRING_EQUAL(reply->str, "OK");
	ASSERT_PASSED(SUITE_SCOPE->asserter.iterateUpTo(
	    15, [&actualTopic] { return LOOP_ASSERTION(actualTopic.has_value()); },
	    // Observed on Rocky 8 with Redis 5.0.3: When the previous test inserted a record, it can take hundreds of
	    // milliseconds, but Redis does eventually notify the expiration of the key (even if the key itself had a 20ms
	    // lifetime). (My best guess is that Redis starts counting from the moment it has finished inserting the data
	    // into its hashmap, so if it was busy with something else -- like another insertion -- everything gets delayed)
	    1s));
	BC_HARD_ASSERT(actualTopic.has_value());
	BC_ASSERT_CPP_EQUAL(*actualTopic, topic);
}

void periodic_replication_check() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const auto connectionListener = std::make_shared<SuccessfulConnectionListener>();
	auto reCheckDelay = SUITE_SCOPE->proxyServer.getAgent()
	                        ->getConfigManager()
	                        .getRoot()
	                        ->get<GenericStruct>("module::Registrar")
	                        ->get<ConfigDuration<std::chrono::seconds>>("redis-slave-check-period")
	                        ->read();
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&registrar] { return registrar.isWritable(); }));
	registrar.addStateListener(connectionListener);

	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.waitUntil(
	    reCheckDelay + 1s, [&reCheckDone = connectionListener->called] { return reCheckDone; }));

	BC_ASSERT(connectionListener->successful);
}

/**
 * What happens when the Redis backend gets denied access to subscribe to some pattern?
 * For convenience, this test disables all SUBSCRIBE commands, but the behaviour is identical when using pub/sub channel
 * pattern restrictions.
 *
 * The Registrar simply logs errors (untested) as it keeps attempting to re-subscribe. When permissions are restored, it
 * successfully re-subscribes, and PUBLISHes get through.
 */
void no_perm_to_subscribe() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const auto& topic = Record::Key(SipUri("sip:subscription-failed@example.org"), registrar.useGlobalDomain());
	auto actualTopic = std::optional<Record::Key>();
	const auto& listener = std::make_shared<ContactRegisteredCallback>(
	    [&actualTopic](const std::shared_ptr<Record>& record, const auto& userId) {
		    BC_ASSERT_CPP_EQUAL(userId, "'stub-payload'");
		    actualTopic = record->getKey();
	    });
	auto ctx = RedisSyncContext(redisConnect("localhost", SUITE_SCOPE->redis.port()));
	{ // Sabotage SUBSCRIBE commands
		const auto reply = ctx.command("ACL SETUSER default -subscribe");
		if (reply->type == REDIS_REPLY_ERROR) {
			SLOGW << "tester: This Redis server does not support Access Control Lists. "
			         "We therefore have no way to test the target code path, but also, consequently, no way for it to "
			         "be reached by such a version of Redis, so we can arguably consider the test passed, and just "
			         "abort now.";
			return;

		} else {
			BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
			BC_ASSERT_STRING_EQUAL(reply->str, "OK");
		}
	}
	const auto isNewSubscription = registrar.subscribe(topic, listener);
	BC_HARD_ASSERT(isNewSubscription);
	const auto& publish = [&ctx, &channel = topic.asString()]() {
		const auto reply = ctx.command("PUBLISH %s 'stub-payload'", channel.c_str());
		BC_HARD_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_INTEGER);
		return reply->integer;
	};
	constexpr auto maxIterations = 4;
	constexpr auto maxDuration = 100ms;

	// The registrar could not subscribe, so there is no one to receive PUBLISHes
	const auto& someSubscriberReceivedIt = SUITE_SCOPE->asserter.iterateUpTo(
	    maxIterations, [&publish] { return LOOP_ASSERTION(0 < publish()); }, maxDuration);
	BC_ASSERT_FALSE(someSubscriberReceivedIt);

	{ // Restore SUBSCRIBE commands
		const auto reply = ctx.command("ACL SETUSER default +subscribe");
		BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
		BC_ASSERT_STRING_EQUAL(reply->str, "OK");
	}

	SUITE_SCOPE->asserter
	    .iterateUpTo(
	        maxIterations,
	        [&publish] {
		        // Publish until someone has received it
		        return LOOP_ASSERTION(0 < publish());
	        },
	        maxDuration)
	    .assert_passed();
	SUITE_SCOPE->asserter
	    .iterateUpTo(
	        1, [&actualTopic] { return LOOP_ASSERTION(actualTopic.has_value()); }, 100ms)
	    .assert_passed();
	BC_HARD_ASSERT(actualTopic.has_value());
	BC_ASSERT_CPP_EQUAL(*actualTopic, topic);
}

// Trigger the single-instance specialisation of `.fetch()` that attempts to HGET a single device/contact in the AoR,
// but with a non-existant gruu. Assert that the listener is called back with a null record.
// This use-case was broken when the hiredis wrapper was introduced
void doFetchInstance_not_found() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const auto& listener = std::make_shared<NullRecordListener>();

	registrar.fetch(SipUri("sip:stub@127.0.0.1;gr=non-existant-gruu"), listener);

	const auto& callCount = listener->callCount;
	SUITE_SCOPE->asserter.iterateUpTo(10, [&] { return LOOP_ASSERTION(0 < callCount); }).assert_passed();
	BC_ASSERT_CPP_EQUAL(callCount, 1);
}

TestSuite main("RegistrarDbRedis",
               {
                   CLASSY_TEST(mContext_should_be_checked_on_serializeAndSendToRedis),
                   CLASSY_TEST(auto_connect_on_command),
                   CLASSY_TEST(bindRetryOnBrokenConnection),
                   CLASSY_TEST(subscribeToKeyExpiration),
                   CLASSY_TEST(periodic_replication_check),
                   CLASSY_TEST(no_perm_to_subscribe),
                   CLASSY_TEST(doFetchInstance_not_found),
               },
               Hooks()
                   .beforeSuite([]() {
	                   SUITE_SCOPE.emplace();
	                   return 0;
                   })
                   .afterSuite([]() {
	                   SUITE_SCOPE.reset();
	                   return 0;
                   }));

// --- Edge Cases ---
// As a different suite to avoid trampling the RegistrarDb

class PreventOpeningNewFileDescriptors {
public:
	PreventOpeningNewFileDescriptors() {
		// Save current limits
		BC_HARD_ASSERT(getrlimit(RLIMIT_NOFILE, &mLimits) != -1);
		mPrevious = mLimits.rlim_cur;
		// Override soft limit
		mLimits.rlim_cur = 0;
		BC_HARD_ASSERT(setrlimit(RLIMIT_NOFILE, &mLimits) != -1);
	}
	~PreventOpeningNewFileDescriptors() {
		// Restore previous limit(s)
		mLimits.rlim_cur = mPrevious;
		BC_HARD_ASSERT(setrlimit(RLIMIT_NOFILE, &mLimits) != -1);
	}

private:
	struct rlimit mLimits;
	rlim_t mPrevious;
};

void connection_failure() {
	Server proxyServer{
	    {{"module::Registrar/db-implementation", "redis"},
	     {"module::Registrar/redis-server-domain", "localhost"},
	     {"module::Registrar/redis-server-port", "0"}},
	};
	CoreAssert asserter{proxyServer};
	auto& registrar = proxyServer.getAgent()->getRegistrarDb();
	auto backend = dynamic_cast<const RegistrarDbRedisAsync*>(&registrar.getRegistrarBackend());
	BC_HARD_ASSERT(backend != nullptr);
	auto& registrarBackend = const_cast<RegistrarDbRedisAsync&>(*backend); // we want to force a behavior
	auto listener = std::make_shared<OperationFailedListener>();
	BC_ASSERT(registrarBackend.connect() != std::nullopt);

	registrar.fetch(SipUri("sip:connection-failure@example.org"), listener);
	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&finished = listener->finished] { return finished; }));

	// Test error on context initialisation
	RegistrarDbRedisAsync::forceDisconnectForTest(registrarBackend);
	listener->finished = false;
	// Sabotage network sockets
	PreventOpeningNewFileDescriptors _{};

	BC_ASSERT(registrarBackend.connect() == std::nullopt);
	registrar.fetch(SipUri("sip:connection-failure@example.org"), listener);
	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&finished = listener->finished] { return finished; }));
}

TestSuite edgeCases("RegistrarDbRedis-EdgeCases",
                    {
                        CLASSY_TEST(connection_failure),
                    });
} // namespace
} // namespace flexisip::tester::registrardb_redis
