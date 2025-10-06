/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "tester.hh"
#include "utils/core-assert.hh"
#include "utils/redis-sync-access.hh"
#include "utils/server/redis-server.hh"
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

/**
 * Check if RedisClient can connect to a Redis server using TLS connection
 *
 * There are two modes possible:
 * - Mutual TLS:	Both the client and the server need to use a certificate and key
 * - NoClientAuth:	Only the server needs to authentify itself
 */
template <const RedisServer::TlsMode tlsMode>
void tlsConnection() {
	const std::string certFile = bcTesterRes("cert/redis/redis.crt");
	const std::string keyFile = bcTesterRes("cert/redis/redis.key");
	const std::string caFile = bcTesterRes("cert/redis/ca.crt");

	const auto& auth = auth::Legacy{.password = "There is no 55"};
	auto redisMaster = RedisServer({
	    .requirepass = auth.password,
	    .tlsMode = tlsMode,
	    .tls =
	        {
	            .cert = certFile,
	            .key = keyFile,
	            .caFile = tlsMode == RedisServer::TlsMode::mutual ? caFile : "",
	        },
	});
	auto root = make_shared<sofiasip::SuRoot>();

	const ConnectionParameters connectionParams{
	    .connectionType =
	        tlsMode == RedisServer::TlsMode::mutual ? ConnectionType::mutualTls : ConnectionType::serverSideTls,
	    .tlsCert = tlsMode == RedisServer::TlsMode::mutual ? certFile : "",
	    .tlsKey = tlsMode == RedisServer::TlsMode::mutual ? keyFile : "",
	    .tlsCaFile = caFile,
	};
	const auto& params = RedisParameters{
	    .domain = "127.0.0.1",
	    .auth = auth,
	    .port = redisMaster.port(),
	    .mSlaveCheckTimeout = 0xbeads,
	    .mSubSessionKeepAliveTimeout = 60s,
	    .connectionParameters = connectionParams,
	};
	auto listener = ClientListener();
	auto client = RedisClient(root, params, SoftPtr<SessionListener>::fromObjectLivingLongEnough(listener));
	auto asserter = CoreAssert(root);
	auto writeCommandReturned = false;

	BC_ASSERT(!listener.connected);

	client.connect();
	std::ignore =
	    asserter.iterateUpTo(6, [&listener]() { return LOOP_ASSERTION(listener.connected); }, 200ms).assert_passed();
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
	std::ignore =
	    asserter.iterateUpTo(
	                1, [&writeCommandReturned]() { return LOOP_ASSERTION(writeCommandReturned); }, 100ms)
	        .assert_passed();
}

TestSuite _("redis::async::RedisClientTls",
            {
                CLASSY_TEST(tlsConnection<RedisServer::TlsMode::mutual>),
                CLASSY_TEST(tlsConnection<RedisServer::TlsMode::noClientAuth>),
            });

} // namespace

} // namespace flexisip::tester
