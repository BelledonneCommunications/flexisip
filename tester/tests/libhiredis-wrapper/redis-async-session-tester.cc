/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "libhiredis-wrapper/redis-async-session.hh"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <variant>
#include <vector>

#include "bctoolbox/tester.h"

#include "flexisip/sofia-wrapper/su-root.hh"

#include "compat/hiredis/hiredis.h"

#include "libhiredis-wrapper/redis-reply.hh"
#include "utils/core-assert.hh"
#include "utils/soft-ptr.hh"
#include "utils/redis-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/variant-utils.hh"

using namespace std::string_literals;

namespace flexisip::tester {

namespace {

// This context will be shared by all tests of the suite. Be mindful of side-effects.
// As of 2024-01-03, this suite only ever reads from Redis, so it's okay to share the same instance and save some 10s
// of test time (Redis startup time is a bit over 1s on my machine)
struct SuiteScope {
	RedisServer redis{};
	sofiasip::SuRoot root{};
	CoreAssert asserter{root};

	template <typename TSession>
	auto& connect(TSession& session) {
		return session.connect(root.getCPtr(), "localhost", redis.port());
	}
};

std::optional<SuiteScope> SUITE_SCOPE;

} // namespace

struct TestSessionListener : redis::async::SessionListener {
	bool connected = false;

	void onConnect(int status) override {
		BC_ASSERT_CPP_EQUAL(status, REDIS_OK);
		connected = true;
	}
};

void commandSession_connectThenSendCommand() {
	auto& asserter = SUITE_SCOPE->asserter;
	TestSessionListener listener{};
	redis::async::Session session{SoftPtr<redis::async::SessionListener>::fromObjectLivingLongEnough(listener)};
	BC_ASSERT_TRUE(std::holds_alternative<redis::async::Session::Disconnected>(session.getState()));

	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);
	BC_ASSERT_FALSE(ready->connected());

	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&connected = listener.connected]() { return connected; }));

	BC_HARD_ASSERT_CPP_EQUAL(std::get_if<redis::async::Session::Ready>(&session.getState()), ready);
	BC_HARD_ASSERT(ready->connected());
	bool returned = false;
	ready->command({"PING", "expected string"}, [&returned](decltype(session)&, redis::async::Reply reply) {
		const auto* echo = std::get_if<redis::reply::String>(&reply);
		BC_HARD_ASSERT_TRUE(echo != nullptr);
		BC_ASSERT(*echo == "expected string");
		returned = true;
	});

	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&returned]() { return returned; }));
}

void commandSession_cleanDisconnectFinishesPendingCommands() {
	auto& asserter = SUITE_SCOPE->asserter;
	TestSessionListener listener{};
	redis::async::Session session{SoftPtr<redis::async::SessionListener>::fromObjectLivingLongEnough(listener)};
	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);
	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&connected = listener.connected]() { return connected; }));
	BC_HARD_ASSERT_CPP_EQUAL(std::get_if<redis::async::Session::Ready>(&session.getState()), ready);
	BC_HARD_ASSERT(ready->connected());
	bool returned = false;

	ready->command({"HGETALL", "*"}, [&returned](decltype(session)&, redis::async::Reply reply) {
		const auto* array = std::get_if<redis::reply::Array>(&reply);
		BC_HARD_ASSERT_TRUE(array != nullptr);
		BC_ASSERT_CPP_EQUAL(array->size(), 0);
		returned = true;
	});

	BC_ASSERT_TRUE(std::holds_alternative<redis::async::Session::Disconnecting>(session.disconnect()));
	BC_ASSERT_TRUE(std::holds_alternative<redis::async::Session::Disconnecting>(session.getState()));
	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&returned]() { return returned; }));
	BC_ASSERT_TRUE(std::holds_alternative<redis::async::Session::Disconnected>(session.getState()));
}

void commandSession_earlyCommand() {
	auto& asserter = SUITE_SCOPE->asserter;
	redis::async::Session session{};
	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);
	BC_ASSERT_FALSE(ready->connected()); // Not connected yet
	bool returned = false;

	ready->command({"ECHO", "expected string"}, [&returned](decltype(session)&, redis::async::Reply reply) {
		const auto* echo = std::get_if<redis::reply::String>(&reply);
		BC_HARD_ASSERT_TRUE(echo != nullptr);
		BC_ASSERT(*echo == "expected string");
		returned = true;
	});

	BC_ASSERT_TRUE(asserter.iterateUpTo(1, [&returned]() { return returned; }));
	BC_ASSERT(ready->connected());
}

void commandSession_connectIsIdempotent() {
	redis::async::Session session{};
	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);

	const auto& connectionResult = SUITE_SCOPE->connect(session);

	BC_HARD_ASSERT_CPP_EQUAL(std::get_if<redis::async::Session::Ready>(&connectionResult), ready);
}

void commandSession_cannotSendSubscriptionCommands() {
	redis::async::Session session{};
	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);

	for (auto command : {
	         "SUBSCRIBE",
	         "UNSUBSCRIBE",
	         "PSUBSCRIBE",
	         "PUNSUBSCRIBE",
	         "SSUBSCRIBE",
	         "SUNSUBSCRIBE",
	         "subscribe",
	         "unsubscribe",
	         "sUbScrIbe",
	     }) {
		try {
			ready->command({command, "stub topic"}, {});
			BC_HARD_FAIL(
			    ("Hiredis wrapper failed to prevent use of "s + command + " command in a non-subscribed context")
			        .c_str());
		} catch (const std::invalid_argument&) {
			// Success!
		}
	}
}

void commandSession_exceptionInCallback() {
	redis::async::Session session{};
	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);
	bool returned = false;

	ready->command({"PING", "expected string"}, [&returned](auto&, auto) {
		returned = true;
		throw std::runtime_error{"woops"};
	});
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&returned]() { return returned; }));

	// Did not crash
}

void commandSession_destructionBeforeConnection() {
	redis::async::Session session{};
	auto* ready = std::get_if<redis::async::Session::Ready>(&SUITE_SCOPE->connect(session));
	BC_HARD_ASSERT(ready != nullptr);
	BC_ASSERT(!ready->connected());

	// Destruct everything, see if there's any crash or leak
}

void subscriptionsSession_exceptionInCallback() {
	redis::async::SubscriptionSession subscriptionsSession{};
	auto* subsReady = std::get_if<decltype(subscriptionsSession)::Ready>(&SUITE_SCOPE->connect(subscriptionsSession));
	BC_HARD_ASSERT(subsReady != nullptr);
	bool called = false;

	subsReady->subscriptions()["stub topic"].subscribe([&called](auto, auto reply) {
		// Prevent use after free when called in the subscription session's destructor
		if (std::holds_alternative<redis::reply::Disconnected>(reply)) return;

		called = true;
		throw std::runtime_error{"woopsie"};
	});
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&called]() { return called; }));

	// Did not crash
}

void subscriptionsSession_autoReSub() {
	redis::async::Session commandsSession{};
	redis::async::SubscriptionSession subscriptionsSession{};
	auto* commands = std::get_if<decltype(commandsSession)::Ready>(&SUITE_SCOPE->connect(commandsSession));
	BC_HARD_ASSERT(commands != nullptr);
	auto* subscriptions =
	    std::get_if<decltype(subscriptionsSession)::Ready>(&SUITE_SCOPE->connect(subscriptionsSession));
	BC_HARD_ASSERT(subscriptions != nullptr);
	std::string topic = "stub topic";
	std::string payload = "";
	bool subscribed = false;

	subscriptions->subscriptions()[topic].subscribe([&payload, &subscribed](auto, redis::async::Reply reply) {
		const auto array = EXPECT_VARIANT(redis::reply::Array).in(std::move(reply));
		const auto type = EXPECT_VARIANT(redis::reply::String).in(array[0]);
		if (type == "subscribe") {
			subscribed = true;
			return;
		}
		if (type != "message") return;
		payload = EXPECT_VARIANT(redis::reply::String).in(array[2]);
	});
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&subscribed]() { return subscribed; }));
	commands->command({"PUBLISH", topic, "first payload"}, {});
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&payload]() { return !payload.empty(); }));

	BC_ASSERT_CPP_EQUAL(payload, "first payload");

	// Publish again within the same session
	payload = "";
	commands->command({"PUBLISH", topic, "second payload"}, {});
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&payload]() { return !payload.empty(); }));

	BC_ASSERT_CPP_EQUAL(payload, "second payload");

	// Reconnect subscription session and publish again
	payload = "";
	subscribed = false;
	BC_ASSERT_TRUE(std::holds_alternative<redis::async::Session::Disconnected>(subscriptionsSession.disconnect()));
	subscriptions = std::get_if<decltype(subscriptionsSession)::Ready>(&SUITE_SCOPE->connect(subscriptionsSession));
	BC_HARD_ASSERT(subscriptions != nullptr);
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&subscribed]() { return subscribed; }));
	commands->command({"PUBLISH", topic, "third payload"}, {});
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&payload]() { return !payload.empty(); }));

	BC_ASSERT_CPP_EQUAL(payload, "third payload");
}

void subscriptionsSession_subscriptionFreedOnUnsubscribe() {
	static constexpr std::string_view topic{"subscription freed on unsubscribe"};
	redis::async::SubscriptionSession subscriptionsSession{};
	auto* subsReady = std::get_if<decltype(subscriptionsSession)::Ready>(&SUITE_SCOPE->connect(subscriptionsSession));
	BC_HARD_ASSERT(subsReady != nullptr);
	auto subscriptions = subsReady->subscriptions();
	bool subscribed = false;
	const auto capturedData = std::make_shared<std::nullptr_t>();
	BC_ASSERT_CPP_EQUAL(capturedData.use_count(), 1);
	subscriptions[topic].subscribe([&subscribed, capturedData](auto, auto) { subscribed = true; });
	BC_ASSERT_TRUE(SUITE_SCOPE->asserter.iterateUpTo(1, [&subscribed]() { return subscribed; }));
	BC_ASSERT_CPP_EQUAL(subscriptions.size(), 1);
	BC_ASSERT_CPP_EQUAL(capturedData.use_count(), 2);

	{
		auto subscription = subscriptions[topic];
		BC_ASSERT(subscription.subscribed());
		subscription.unsubscribe();
	}

	BC_ASSERT_TRUE(
	    SUITE_SCOPE->asserter.iterateUpTo(1, [&subscriptions]() { return !subscriptions[topic].subscribed(); }));
	BC_ASSERT_CPP_EQUAL(subscriptions.size(), 0);
	BC_ASSERT_CPP_EQUAL(capturedData.use_count(), 1);
}

namespace {
TestSuite _("redis::async::Context",
            {
                CLASSY_TEST(commandSession_connectThenSendCommand),
                CLASSY_TEST(commandSession_cleanDisconnectFinishesPendingCommands),
                CLASSY_TEST(commandSession_earlyCommand),
                CLASSY_TEST(commandSession_connectIsIdempotent),
                CLASSY_TEST(commandSession_cannotSendSubscriptionCommands),
                CLASSY_TEST(commandSession_destructionBeforeConnection),
                CLASSY_TEST(subscriptionsSession_exceptionInCallback),
                CLASSY_TEST(subscriptionsSession_autoReSub),
                CLASSY_TEST(subscriptionsSession_subscriptionFreedOnUnsubscribe),
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
}
} // namespace flexisip::tester
