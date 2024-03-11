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
#include "utils/proxy-server.hh"
#include "utils/redis-server.hh"
#include "utils/redis-sync-access.hh"
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
	CoreAssert asserter{proxyServer};
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
	registrarBackend.asyncDisconnect(); // disconnecting before the previous bind operation finishes

	// The bind() ends in error, but there should be no segfault
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(30, [&finished = listener->finished] { return finished; }));
}

void auto_connect_on_command() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const auto* backend = dynamic_cast<const RegistrarDbRedisAsync*>(&registrar.getRegistrarBackend());
	BC_HARD_ASSERT(backend != nullptr);
	auto& registrarBackend = const_cast<RegistrarDbRedisAsync&>(*backend); // we want to force a behavior

	registrarBackend.forceDisconnect();
	BC_HARD_ASSERT(!registrar.isWritable());

	registrar.fetch(SipUri("sip:redis-auto-connect@example.org"), nullptr);

	// Automatically reconnected to call the command
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&registrar] { return registrar.isWritable(); }));
}

void bind_retry_on_broken_connection() {
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
		if (reply->type == REDIS_REPLY_ERROR) {
			SLOGW << "tester: The Redis server does not support listening for keymiss events."
			         "This test will be less reliable.";
			// Assume the key will be fetched in one iteration of the sofia loop
			// In this case, subscribing is unnecessary but harmless
			keyFetched = true;
		} else {
			BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
			BC_ASSERT_STRING_EQUAL(reply->str, "OK");
		}

		keymissReady->subscriptions()["__keyevent@0__:keymiss"].subscribe([&keyFetched, &subscribed](auto reply) {
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

void subscribe_to_key_expiration() {
	auto& registrar = SUITE_SCOPE->proxyServer.getAgent()->getRegistrarDb();
	const Record::Key topic{SipUri("sip:expiring-key@example.org"), registrar.useGlobalDomain()};
	std::optional<Record::Key> actualTopic{};
	const auto listener = std::make_shared<ContactRegisteredCallback>(
	    [&actualTopic](const std::shared_ptr<Record>& record, const auto& userId) {
		    BC_ASSERT_CPP_EQUAL(userId, "");
		    BC_HARD_ASSERT(record != nullptr);
		    actualTopic = record->getKey();
	    });
	registrar.subscribe(topic, listener);
	RedisSyncContext ctx = redisConnect("localhost", SUITE_SCOPE->redis.port());
	{
		// https://redis.io/docs/manual/keyspace-notifications/
		// Set up key expired event notifications
		const auto reply = ctx.command("CONFIG SET notify-keyspace-events Ex");
		BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
		BC_ASSERT_STRING_EQUAL(reply->str, "OK");
	}

	// SET a key expiring in 1ms
	const auto reply = ctx.command("SET %s 'stub-payload' PX 1", topic.toRedisKey().c_str());
	BC_ASSERT_CPP_EQUAL(reply->type, REDIS_REPLY_STATUS);
	BC_ASSERT_STRING_EQUAL(reply->str, "OK");

	BC_HARD_ASSERT(SUITE_SCOPE->asserter.iterateUpTo(
	    8, [&actualTopic] { return actualTopic.has_value(); }, 200ms));
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

TestSuite main("RegistrarDbRedis",
               {
                   CLASSY_TEST(mContext_should_be_checked_on_serializeAndSendToRedis),
                   CLASSY_TEST(auto_connect_on_command),
                   CLASSY_TEST(bind_retry_on_broken_connection),
                   CLASSY_TEST(subscribe_to_key_expiration),
                   CLASSY_TEST(periodic_replication_check),
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
	registrarBackend.forceDisconnect();
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
