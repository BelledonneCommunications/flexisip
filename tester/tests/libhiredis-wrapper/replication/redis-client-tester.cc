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

#include "libhiredis-wrapper/replication/redis-client.hh"

#include "utils/core-assert.hh"
#include "utils/redis-server.hh"
#include "utils/redis-sync-access.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace {
using namespace redis;
using namespace redis::async;

struct ClientListener : SessionListener {
	bool connected = false;

	void onConnect(int status) override {
		connected = status == REDIS_OK;
	}
	void onDisconnect(int) override {
		connected = false;
	}
};

/* Setup 2 Redis servers with authentication (1 master, 1 replica)
 * Connect the RedisClient to the replica, verify that it auto-reconnects to the master node.
 */
void autoReconnectToMaster() {
	const auto& auth = auth::Legacy{.password = "There is no 55"};
	auto redisMaster = RedisServer({.requirepass = auth.password});
	auto redisReplica = redisMaster.createReplica();
	auto root = sofiasip::SuRoot();
	const auto& params = RedisParameters{
	    .domain = "127.0.0.1",
	    .auth = auth,
	    .port = redisReplica.port(),
	    .mSlaveCheckTimeout = 0xbeads,
	};
	auto listener = ClientListener();
	auto client = RedisClient(root, params, SoftPtr<SessionListener>::fromObjectLivingLongEnough(listener));
	auto asserter = CoreAssert(root);
	auto writeCommandReturned = false;
	{ // Wait for replica to connect to master node
		auto controlSession = RedisSyncContext(redisConnect("127.0.0.1", params.port));
		const auto& response = controlSession.command("AUTH %s", auth.password.c_str());
		BC_HARD_ASSERT_CPP_EQUAL(response->type, REDIS_REPLY_STATUS);
		BC_HARD_ASSERT_CPP_EQUAL(response->str, "OK"sv);
		BcAssert()
		    .iterateUpTo(
		        10,
		        [&controlSession] {
			        const auto& response = controlSession.command("INFO replication");
			        FAIL_IF(response->type != REDIS_REPLY_STRING);
			        const auto& info = string_view(response->str);
			        constexpr auto fieldName = "master_link_status:"sv;
			        const auto index = info.find(fieldName);
			        FAIL_IF(index == info.npos);
			        constexpr auto expectedStatus = "up"sv;
			        return LOOP_ASSERTION(info.substr(index + fieldName.size(), expectedStatus.size()) ==
			                              expectedStatus);
		        },
		        200ms)
		    .assert_passed();
	}

	// Send write command early. It will reach the replica before the client gets a chance to reconnect to the master
	{
		const auto* ready = client.tryGetCmdSession();
		BC_HARD_ASSERT(ready != nullptr);
		ready->command({"SET", "stub-key", "stub-value"}, [&writeCommandReturned](const auto&, Reply reply) {
			writeCommandReturned = true;
			const auto* status = std::get_if<reply::Error>(&reply);
			BC_HARD_ASSERT(status != nullptr);
			constexpr auto expected = "READONLY"sv;
			BC_ASSERT_CPP_EQUAL(status->substr(0, expected.size()), expected);
		});
	}
	asserter
	    .iterateUpTo(
	        1, [&writeCommandReturned]() { return LOOP_ASSERTION(writeCommandReturned); }, 100ms)
	    .assert_passed();

	// Let the client auto-reconnect to the master
	BC_ASSERT(!listener.connected);
	asserter
	    .iterateUpTo(
	        6, [&listener]() { return LOOP_ASSERTION(listener.connected); }, 200ms)
	    .assert_passed();

	// Try sending the write command again. This time it succeeds.
	writeCommandReturned = false;
	{
		const auto* ready = client.tryGetCmdSession();
		BC_HARD_ASSERT(ready != nullptr);
		ready->command({"SET", "stub-key", "stub-value"}, [&writeCommandReturned](const auto&, Reply reply) {
			writeCommandReturned = true;
			const auto* status = std::get_if<reply::Status>(&reply);
			BC_HARD_ASSERT(status != nullptr);
			BC_ASSERT_CPP_EQUAL(*status, "OK");
		});
	}
	asserter
	    .iterateUpTo(
	        1, [&writeCommandReturned]() { return LOOP_ASSERTION(writeCommandReturned); }, 100ms)
	    .assert_passed();
}

TestSuite _("redis::async::RedisClient",
            {
                CLASSY_TEST(autoReconnectToMaster),
            });

} // namespace

} // namespace flexisip::tester
