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

#include "flexisip/configmanager.hh"
#include "flexisip/registrardb.hh"

#include "tester.hh"
#include "utils/redis-server.hh"

using namespace std;

namespace flexisip {
namespace tester {

// Interface for all the classes which are to be executed as unit test.
// The test is executed by calling () operator.
class Test {
public:
	virtual ~Test() = default;
	virtual void operator()() noexcept = 0;
};

// Wrapper object that allow BCUnit to easily call a Test-deviled class.
// It is to be derived by the Test class to wrap by using the name
// of the Test class as TestT template parameter.
// Then, the method TestT::run() can be used in a BCUnit test suite array.
template <typename TestT> class TestWrapper {
public:
	static void run() noexcept {
		TestT test{};
		test();
	}
};

// Base class for all the tests concerning the RegistrarDB class.
// It automatically instantiate an Agent which can be configured
// by redefining onAgentConfiguration() method. Furthermore, it
// ensures that the RegistrarDB singleton is destroyed once the test
// is completed.
// The test can be specialized by redefining onExec() method.
class RegistrarDbTest : public Test {
public:
	~RegistrarDbTest() {
		RegistrarDb::resetDB();
	}

	void operator()() noexcept override {
		configureAgent();
		onExec();
	};

protected:
	// Protected methods
	void configureAgent() {
		auto* cfg = GenericManager::get();
		cfg->load("");
		onAgentConfiguration(*cfg);
		mAgent->loadConfig(cfg, false);
	};

	/**
	 * Run the SofiaSip main loop for a given time.
	 * This methods is to be used by an overload of onExec().
	 */
	template <typename Duration> void waitFor(Duration timeout) noexcept {
		using namespace std::chrono;
		for (auto now = steady_clock::now(), end = now + timeout; now < end; now = steady_clock::now()) {
			mRoot->step(end - now);
		}
	}

	/**
	 * Run the SofiaSip main loop until a given condition is fulfil or the timeout is reached.
	 * This methods is to be used by an overload of onExec().
	 * @return true, if the break condition has been fulfil before the timeout.
	 */
	template <typename Duration> bool waitFor(const std::function<bool()>& breakCondition, Duration timeout) {
		using namespace std::chrono;
		for (auto now = steady_clock::now(), end = now + timeout; now < end; now = steady_clock::now()) {
			if (breakCondition()) return true;
			mRoot->step(end - now);
		}
		return false;
	}

	virtual void onAgentConfiguration(GenericManager& cfg) = 0;
	virtual void onExec() = 0;

	// Protected attributes
	std::shared_ptr<sofiasip::SuRoot> mRoot{std::make_shared<sofiasip::SuRoot>()};
	std::shared_ptr<Agent> mAgent{std::make_shared<Agent>(mRoot)};
};

// Base class for testing UNSUBSCRIBE/SUBSCRIBE scenario.
// That tests that the subscription is still on if subscribe() methods
// is immediately called after unsubscribe(). We found out that with some
// backend (e.g. Redis) that may lead to a race condition that caused the subscription
// to be off.
class SubsequentUnsubscribeSubscribeTest : public RegistrarDbTest {
protected:
	// Protected types
	struct RegistrarStats : public ContactRegisteredListener {
		void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) override {
			++onContactRegisteredCount;
		}

		int onContactRegisteredCount{0};
	};

	// Protected methods
	void onExec() noexcept override {
		auto* regDb = RegistrarDb::get();

		auto stats = make_shared<RegistrarStats>();

		const string topic{"user@sip.example.org"};
		const string uuid{"dummy-uuid"};
		SLOGD << "Subscribing to '" << topic << "'";
		regDb->subscribe(topic, stats);
		waitFor(1s);

		SLOGD << "Notifying topic[" << topic << "] with uuid[" << uuid << "]";
		regDb->publish(topic, uuid);
		BC_ASSERT_TRUE(waitFor([&stats]() { return stats->onContactRegisteredCount >= 1; }, 1s));
		BC_ASSERT_EQUAL(stats->onContactRegisteredCount, 1, int, "%d");

		SLOGD << "Subsequent Redis UNSUBSCRIBE/SUBSCRIBE";
		regDb->unsubscribe(topic, stats);
		regDb->subscribe(topic, stats);
		waitFor(1s);

		SLOGD << "Secondly Notifying topic[" << topic << "] with uuid[" << uuid << "]";
		regDb->publish(topic, uuid);
		BC_ASSERT_TRUE(waitFor([&stats]() { return stats->onContactRegisteredCount >= 2; }, 1s));
		BC_ASSERT_EQUAL(stats->onContactRegisteredCount, 2, int, "%d");
	}
};

// Test UNSUBSCRIBE/SUBSCRIBE scenario with the 'internal' RegistrarDB backend.
class SubsequentUnsubscribeSubscribeWithInternalDbTest
    : public SubsequentUnsubscribeSubscribeTest,
      public TestWrapper<SubsequentUnsubscribeSubscribeWithInternalDbTest> {
protected:
	void onAgentConfiguration(GenericManager& cfg) override {
		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("internal");
	}
};

// Test UNSUBSCRIBE/SUBSCRIBE scenario with the 'redis' RegistrarDB backend.
class SubsequentUnsubscribeSubscribeWithRedisTest : public SubsequentUnsubscribeSubscribeTest,
                                                    public TestWrapper<SubsequentUnsubscribeSubscribeWithRedisTest> {
protected:
	// Protected methods
	void onAgentConfiguration(GenericManager& cfg) override {
		auto redisPort = mRedisServer.start();

		auto* registrarConf = cfg.getRoot()->get<GenericStruct>("module::Registrar");
		registrarConf->get<ConfigValue>("db-implementation")->set("redis");
		registrarConf->get<ConfigValue>("redis-server-domain")->set("localhost");
		registrarConf->get<ConfigValue>("redis-server-port")->set(std::to_string(redisPort));
	}

	// Protected attributes
	RedisServer mRedisServer{};
};

} // namespace tester
} // namespace flexisip

namespace flexisip {
namespace tester {

static test_t tests[] = {TEST_NO_TAG("Subsequent UNSUBSCRIBE/SUBSCRIBE with internal backend",
                                     SubsequentUnsubscribeSubscribeWithInternalDbTest::run),
                         TEST_NO_TAG("Subsequent UNSUBSCRIBE/SUBSCRIBE with Redis backend",
                                     SubsequentUnsubscribeSubscribeWithRedisTest::run)};

test_suite_t registarDbSuite = {
    "RegistrarDB",                    // Suite name
    nullptr,                          // Before suite
    nullptr,                          // After suite
    nullptr,                          // Before each test
    nullptr,                          // After each test
    sizeof(tests) / sizeof(tests[0]), // test array length
    tests                             // test array
};

} // namespace tester
} // namespace flexisip
