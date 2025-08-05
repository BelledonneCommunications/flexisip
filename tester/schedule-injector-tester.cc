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

#include "fork-context/fork-context-factory.hh"
#include "fork-context/fork-message-context-db-proxy.hh"
#include "router/fork-manager.hh"
#include "router/inject-context.hh"
#include "router/schedule-injector.hh"
#include "utils/test-patterns/agent-test.hh"
#include "utils/test-patterns/test.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;
using namespace sofiasip;

namespace flexisip {
namespace tester {
namespace schedule_injector_suite {

//////////////////////////////////////////////////////////////////////////////////////////
//////////////// SUITE UTILITY CLASSES //////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

class FakeModule : public Module {
public:
	explicit FakeModule(Agent* agent, std::unique_ptr<ModuleInfoBase>&& moduleInfo)
	    : Module(agent, moduleInfo.get()), mInfoKeeper(std::move(moduleInfo)) {
	}

	void injectRequestEvent(unique_ptr<RequestSipEvent>&& ev) override {
		mOrderedInjectedRequests.push_back(ev->getMsgSip());
	}

	vector<shared_ptr<MsgSip>> mOrderedInjectedRequests;

protected:
	std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override {
		return std::move(ev);
	};
	std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& ev) override {
		return std::move(ev);
	};

private:
	std::unique_ptr<ModuleInfoBase> mInfoKeeper;
};

class FakeModuleInfo : public ModuleInfoBase {
public:
	FakeModuleInfo(ConfigManager& cfg)
	    : ModuleInfoBase(
	          "FakeModule",
	          "",
	          {}, // empty module will not register
	          static_cast<ModuleInfoBase::ModuleOid>(0xdead),
	          [](GenericStruct&) {},
	          ModuleClass::Experimental,
	          "") {
		declareConfig(*cfg.getEditableRoot());
	}

	std::shared_ptr<Module> create(Agent*) override {
		return std::make_shared<FakeModule>(nullptr, nullptr);
	}
};
class ScheduleInjectorTest : public AgentTest {
public:
	void onAgentConfiguration(ConfigManager& cfg) override {
		AgentTest::onAgentConfiguration(cfg);

		cfg.getRoot()
		    ->get<GenericStruct>("global")
		    ->get<ConfigValue>("transports")
		    ->set("sip:127.0.0.1:0;transport=tcp");
	}

	void ASSERT_CURRENT_INJECT_ORDER(vector<shared_ptr<ForkMessageContext>> expectedOrder) const {
		BC_HARD_ASSERT_CPP_EQUAL(mStubModule->mOrderedInjectedRequests.size(), expectedOrder.size());
		BC_HARD_ASSERT(std::equal(
		    expectedOrder.begin(), expectedOrder.end(), mStubModule->mOrderedInjectedRequests.begin(),
		    [](shared_ptr<ForkMessageContext>& a, shared_ptr<MsgSip>& b) { return a->getEvent().getMsgSip() == b; }));
	}
	void onAgentConfigured() override {
		mRouterModule = dynamic_pointer_cast<ModuleRouter>(mAgent->findModule("Router"));
		mStubModule = make_shared<FakeModule>(mAgent.get(), make_unique<FakeModuleInfo>(*mConfigManager));
		mInjector = make_unique<ScheduleInjector>(mStubModule.get());
	}

	unique_ptr<RequestSipEvent> makeRequest(const shared_ptr<ForkMessageContext>& fork) {
		return make_unique<RequestSipEvent>(mAgent, fork->getEvent().getMsgSip());
	}

protected:
	std::shared_ptr<ForkMessageContext> addFork(MsgSipPriority priority) {
		string rawRequest{R"sip(MESSAGE sip:alexstrasza.dragon.queen@sip.linphone.org SIP/2.0
Via: SIP/2.0/TLS [2a01:e0a:278:9f60:7a23:c334:1651:2503]:36676;branch=z9hG4bK.ChN0lTDpQ;rport
From: <sip:elenia@sip.linphone.org>;tag=iXiKd6FuX
To: sip:alexstrasza.dragon.queen@sip.linphone.org
CSeq: 20 MESSAGE
Call-ID: NISmf-QTgo
Max-Forwards: 70
Supported: replaces, outbound, gruu
Date: Wed, 06 Oct 2021 08:43:31 GMT
Content-Type: text/plain
Content-Length: 4
User-Agent: Linphone Desktop/4.3.0-beta-33-gc3ac9637 (Manjaro Linux, Qt 5.12.5) LinphoneCore/5.0.22-1-g8c5243994
Proxy-Authorization:  Digest realm="sip.linphone.org", nonce="1tMH5QAAAABVHBjkAADjdHyvMMkAAAAA", algorithm=SHA-256, opaque="+GNywA==", username="elenia",  uri="sip:alexstrasza.dragon.queen@sip.linphone.org", response="787857520cf0cd3f3f451ff7e867aa03536e8a7fed461fe2d14569d928f9296d", cnonce="UVZ7dG3P9Kx6j0na", nc=0000003f, qop=auth

\0st)sip"};

		std::time_t t = system_clock::to_time_t(system_clock::now());
		ForkMessageContextDb fakeDbObject{1, 3, true, *gmtime(&t), rawRequest, priority};
		fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
		const auto forkFactory = mRouterModule->getForkManager()->getFactory();
		auto fork = forkFactory->restoreForkMessageContext(fakeDbObject, weak_ptr<ForkContextListener>{});

		mInjector->addContext(fork, mUuid);

		return fork;
	}

	shared_ptr<ModuleRouter> mRouterModule;
	shared_ptr<FakeModule> mStubModule;
	std::unique_ptr<ScheduleInjector> mInjector;
	const string mUuid = "aRandomUUID";
};

//////////////////////////////////////////////////////////////////////////////////////////
//////////////// SUITE TESTS /////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

template <sofiasip::MsgSipPriority priority>
class OneListTest : public ScheduleInjectorTest {
public:
	void testExec() override {
		const auto fork1 = this->addFork(priority);
		const auto fork2 = this->addFork(priority);
		const auto fork3 = this->addFork(priority);
		const auto fork4 = this->addFork(priority);
		const auto fork5 = this->addFork(priority);
		vector<shared_ptr<ForkMessageContext>> expectedOrder{};

		mInjector->injectRequestEvent(makeRequest(fork5), fork5, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->injectRequestEvent(makeRequest(fork1), fork1, mUuid);
		expectedOrder.push_back(fork1);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->injectRequestEvent(makeRequest(fork3), fork3, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->removeContext(fork2, mUuid);
		expectedOrder.push_back(fork3);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->injectRequestEvent(makeRequest(fork4), fork4, mUuid);
		expectedOrder.push_back(fork4);
		expectedOrder.push_back(fork5);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		const auto fork6 = this->addFork(priority);
		mInjector->removeContext(fork6, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		const auto fork7 = this->addFork(priority);
		mInjector->injectRequestEvent(makeRequest(fork7), fork7, mUuid);
		expectedOrder.push_back(fork7);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
	}
};

template <sofiasip::MsgSipPriority highPriority, sofiasip::MsgSipPriority lowPriority>
class TwoListTest : public ScheduleInjectorTest {
public:
	void testExec() override {
		auto hFork1 = this->addFork(highPriority);
		auto hFork2 = this->addFork(highPriority);
		auto lFork1 = this->addFork(lowPriority);
		auto lFork2 = this->addFork(lowPriority);
		vector<shared_ptr<ForkMessageContext>> expectedOrder{};

		mInjector->injectRequestEvent(makeRequest(lFork2), lFork2, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
		mInjector->injectRequestEvent(makeRequest(hFork1), hFork1, mUuid);
		expectedOrder.push_back(hFork1);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->removeContext(lFork1, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->injectRequestEvent(makeRequest(hFork2), hFork2, mUuid);
		expectedOrder.push_back(hFork2);
		expectedOrder.push_back(lFork2);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		auto lFork3 = this->addFork(lowPriority);
		auto hFork3 = this->addFork(highPriority);
		mInjector->removeContext(lFork3, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->injectRequestEvent(makeRequest(hFork3), hFork3, mUuid);
		expectedOrder.push_back(hFork3);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
	}
};

class AllListTest : public ScheduleInjectorTest {
public:
	void testExec() override {
		vector<shared_ptr<ForkMessageContext>> nonUrgentList{};
		vector<shared_ptr<ForkMessageContext>> normalList{};
		vector<shared_ptr<ForkMessageContext>> urgentList{};
		vector<shared_ptr<ForkMessageContext>> emergencyList{};

		for (int i = 0; i < 5; i++) {
			nonUrgentList.push_back(this->addFork(sofiasip::MsgSipPriority::NonUrgent));
			normalList.push_back(this->addFork(sofiasip::MsgSipPriority::Normal));
			urgentList.push_back(this->addFork(sofiasip::MsgSipPriority::Urgent));
			emergencyList.push_back(this->addFork(sofiasip::MsgSipPriority::Emergency));
		}

		for (int i = 4; i >= 0; i--) {
			mInjector->injectRequestEvent(makeRequest(nonUrgentList[i]), nonUrgentList[i], mUuid);
			mInjector->injectRequestEvent(makeRequest(urgentList[i]), urgentList[i], mUuid);
			mInjector->injectRequestEvent(makeRequest(normalList[i]), normalList[i], mUuid);
			mInjector->injectRequestEvent(makeRequest(emergencyList[i]), emergencyList[i], mUuid);
		}

		vector<shared_ptr<ForkMessageContext>> expectedOrder{emergencyList};
		expectedOrder.insert(expectedOrder.end(), urgentList.begin(), urgentList.end());
		expectedOrder.insert(expectedOrder.end(), normalList.begin(), normalList.end());
		expectedOrder.insert(expectedOrder.end(), nonUrgentList.begin(), nonUrgentList.end());

		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
	}
};

class NonBlockingRemoveScheduleInjectorTest : public ScheduleInjectorTest {
public:
	void testExec() override {
		auto nonUrgentFork = this->addFork(sofiasip::MsgSipPriority::NonUrgent);
		auto normalFork = this->addFork(sofiasip::MsgSipPriority::Normal);
		auto urgentFork = this->addFork(sofiasip::MsgSipPriority::Urgent);
		auto emergencyFork1 = this->addFork(sofiasip::MsgSipPriority::Emergency);
		auto emergencyFork2 = this->addFork(sofiasip::MsgSipPriority::Emergency);

		mInjector->injectRequestEvent(makeRequest(emergencyFork2), emergencyFork2, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});
		mInjector->injectRequestEvent(makeRequest(urgentFork), urgentFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});
		mInjector->injectRequestEvent(makeRequest(normalFork), normalFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});
		mInjector->injectRequestEvent(makeRequest(nonUrgentFork), nonUrgentFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});

		mInjector->removeContext(emergencyFork1, mUuid);
		vector<shared_ptr<ForkMessageContext>> expectedOrder{emergencyFork2, urgentFork, normalFork, nonUrgentFork};
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
	}
};

class BorderLineCasesTest : public ScheduleInjectorTest {
public:
	void testExec() override {
		auto nonUrgentFork = this->addFork(sofiasip::MsgSipPriority::NonUrgent);
		auto nonUrgentFork2 = this->addFork(sofiasip::MsgSipPriority::NonUrgent);
		vector<shared_ptr<ForkMessageContext>> expectedOrder{};

		mInjector->injectRequestEvent(makeRequest(nonUrgentFork), nonUrgentFork, "BAD_UUID");
		// This should not happen, but we prefer to send in wrong order than not at all.
		expectedOrder.push_back(nonUrgentFork);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector->injectRequestEvent(makeRequest(nonUrgentFork), nonUrgentFork, mUuid);
		expectedOrder.push_back(nonUrgentFork);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
		// Injected while not in the list anymore, this should not happen, but we prefer to send in wrong order than not
		// at all.
		mInjector->injectRequestEvent(makeRequest(nonUrgentFork), nonUrgentFork, mUuid);
		expectedOrder.push_back(nonUrgentFork);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		// No crash double remove
		mInjector->removeContext(nonUrgentFork2, mUuid);
		mInjector->removeContext(nonUrgentFork2, mUuid);

		// List is still usable
		auto nonUrgentFork3 = this->addFork(sofiasip::MsgSipPriority::NonUrgent);
		mInjector->injectRequestEvent(makeRequest(nonUrgentFork3), nonUrgentFork3, mUuid);
		expectedOrder.push_back(nonUrgentFork3);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
	}
};

class InjectContextExpiredTest : public ScheduleInjectorTest {
public:
	void testExec() override {
		InjectContext::setMaxRequestRetentionTime(50ms);
		auto nonUrgentFork = this->addFork(sofiasip::MsgSipPriority::NonUrgent);
		auto normalFork = this->addFork(sofiasip::MsgSipPriority::Normal);
		auto urgentFork = this->addFork(sofiasip::MsgSipPriority::Urgent);
		auto emergencyFork1 = this->addFork(sofiasip::MsgSipPriority::Emergency);
		auto emergencyFork2 = this->addFork(sofiasip::MsgSipPriority::Emergency);

		mInjector->injectRequestEvent(makeRequest(emergencyFork2), emergencyFork2, mUuid);
		mInjector->injectRequestEvent(makeRequest(normalFork), normalFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});

		this_thread::sleep_for(50ms);

		mInjector->injectRequestEvent(makeRequest(nonUrgentFork), nonUrgentFork, mUuid);
		vector<shared_ptr<ForkMessageContext>> expectedOrder{emergencyFork2, normalFork, nonUrgentFork};
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
	}
};

auto _ = [] {
	// Work around because TEST_NO_TAG macro can't handle ",".
	using TwoListTestEU = TwoListTest<MsgSipPriority::Emergency, MsgSipPriority::Urgent>;
	using TwoListTestEN = TwoListTest<MsgSipPriority::Emergency, MsgSipPriority::Normal>;
	using TwoListTestENu = TwoListTest<MsgSipPriority::Emergency, MsgSipPriority::NonUrgent>;
	using TwoListTestUN = TwoListTest<MsgSipPriority::Urgent, MsgSipPriority::Normal>;
	using TwoListTestUnu = TwoListTest<MsgSipPriority::Urgent, MsgSipPriority::NonUrgent>;
	using TwoListTestNN = TwoListTest<MsgSipPriority::Normal, MsgSipPriority::NonUrgent>;

	static test_t tests[] = {
	    TEST_NO_TAG("One list test, emergency", run<OneListTest<MsgSipPriority::Emergency>>),
	    TEST_NO_TAG("One list test, urgent", run<OneListTest<MsgSipPriority::Urgent>>),
	    TEST_NO_TAG("One list test, normal", run<OneListTest<MsgSipPriority::Normal>>),
	    TEST_NO_TAG("One list test, non-urgent", run<OneListTest<MsgSipPriority::NonUrgent>>),
	    TEST_NO_TAG("Two list test, emergency/urgent", run<TwoListTestEU>),
	    TEST_NO_TAG("Two list test, emergency/normal", run<TwoListTestEN>),
	    TEST_NO_TAG("Two list test, emergency/non-urgent", run<TwoListTestENu>),
	    TEST_NO_TAG("Two list test, urgent/normal", run<TwoListTestUN>),
	    TEST_NO_TAG("Two list test, urgent/non-urgent", run<TwoListTestUnu>),
	    TEST_NO_TAG("Two list test, normal/non-urgent", run<TwoListTestNN>),
	    TEST_NO_TAG("All list test", run<AllListTest>),
	    TEST_NO_TAG("Test that remove restart injection of waiting forks.", run<NonBlockingRemoveScheduleInjectorTest>),
	    TEST_NO_TAG("Test borderline cases (bad contactID, double remove...)", run<BorderLineCasesTest>),
	    TEST_NO_TAG("Test that expired InjectContext are ignored", run<InjectContextExpiredTest>),
	};
	static test_suite_t scheduleInjectorSuite = {
	    "ScheduleInjector", nullptr, nullptr, nullptr, nullptr, sizeof(tests) / sizeof(tests[0]), tests,
	};
	bc_tester_add_suite(&scheduleInjectorSuite);
	return nullptr;
}();

} // namespace schedule_injector_suite
} // namespace tester
} // namespace flexisip
