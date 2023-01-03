/** Copyright (C) 2010-2022 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <chrono>

#include "utils/asserts.hh"
#include "utils/proxy-server.hh"
#include "utils/redis-server.hh"

#include "registrardb-redis.hh"
#include "utils/test-suite.hh"

using namespace std::chrono_literals;

namespace flexisip {
namespace tester {
namespace registrardb_redis {

class OperationFailedListener : public ContactUpdateListener {
public:
	bool finished = false;

	OperationFailedListener() {
	}

	void onRecordFound(const std::shared_ptr<Record>& r) override {
		BC_FAIL(unexpected call to onRecordFound);
	}
	void onError() override {
		finished = true;
	}
	void onInvalid() override {
		BC_FAIL(unexpected call to onInvalid);
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>& ec) override {
		BC_FAIL(unexpected call to onContactUpdated);
	}
};

void mContext_should_be_checked_on_serializeAndSendToRedis() {
	RedisServer redis;
	Server proxyServer({{"module::Registrar/db-implementation", "redis"},
	                    {"module::Registrar/redis-server-domain", "localhost"},
	                    {"module::Registrar/redis-server-port", std::to_string(redis.start())}});
	BcAssert asserter{};
	asserter.addCustomIterate([&root = *proxyServer.getRoot()] { root.step(1ms); });
	auto& registrar = *dynamic_cast<RegistrarDbRedisAsync*>(RegistrarDb::get());
	const auto placeholder = "sip:placeholder@example.org";
	BindingParameters bindParams;
	bindParams.globalExpire = 3001;
	bindParams.callId = __FUNCTION__;
	sofiasip::Home home{};
	auto listener = std::make_shared<OperationFailedListener>();

	registrar.bind(SipUri(placeholder), sip_contact_make(home.home(), placeholder), bindParams, listener);
	registrar.disconnect(); // disconnecting before the previous bind operation finishes

	// The bind() ends in error, but there should be no segfault
	BC_ASSERT_TRUE(asserter.iterateUpTo(30, [&finished = listener->finished] { return finished; }));
}

namespace {
TestSuite _("RegistrarDbRedis",
            {
                TEST_NO_TAG_AUTO_NAMED(mContext_should_be_checked_on_serializeAndSendToRedis),
            });
}
} // namespace registrardb_redis
} // namespace tester
} // namespace flexisip
