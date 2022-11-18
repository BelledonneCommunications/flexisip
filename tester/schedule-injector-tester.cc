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

#include "fork-context/fork-message-context-db-proxy.hh"
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
	explicit FakeModule(Agent* agent) : Module(agent) {
	}

	void injectRequestEvent(const shared_ptr<RequestSipEvent>& ev) override {
		mOrderedInjectedRequests.push_back(ev);
	};

	vector<shared_ptr<RequestSipEvent>> mOrderedInjectedRequests;

protected:
	void onRequest(std::shared_ptr<RequestSipEvent>& ev) override{};
	void onResponse(std::shared_ptr<ResponseSipEvent>& ev) override{};
};

class ScheduleInjectorTest : public AgentTest {
public:
	void onAgentConfiguration(GenericManager& cfg) override {
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
		    [](shared_ptr<ForkMessageContext>& a, shared_ptr<RequestSipEvent>& b) { return a->getEvent() == b; }));
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
		ForkMessageContextDb fakeDbObject{1, 3, true, false, *gmtime(&t), rawRequest, priority};
		fakeDbObject.dbKeys = vector<string>{"key1", "key2", "key3"};
		auto fork = ForkMessageContext::make(mRouterModule, shared_ptr<ForkContextListener>{}, fakeDbObject);

		mInjector.addContext(fork, mUuid);

		return fork;
	}

	shared_ptr<ModuleRouter> mRouterModule = dynamic_pointer_cast<ModuleRouter>(mAgent->findModule("Router"));
	shared_ptr<FakeModule> mStubModule = make_shared<FakeModule>(nullptr);
	ScheduleInjector mInjector{mStubModule.get()};
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

		mInjector.injectRequestEvent(fork5->getEvent(), fork5, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(fork1->getEvent(), fork1, mUuid);
		expectedOrder.push_back(fork1);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(fork3->getEvent(), fork3, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.removeContext(fork2, mUuid);
		expectedOrder.push_back(fork3);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(fork4->getEvent(), fork4, mUuid);
		expectedOrder.push_back(fork4);
		expectedOrder.push_back(fork5);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		const auto fork6 = this->addFork(priority);
		mInjector.removeContext(fork6, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		const auto fork7 = this->addFork(priority);
		mInjector.injectRequestEvent(fork7->getEvent(), fork7, mUuid);
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

		mInjector.injectRequestEvent(lFork2->getEvent(), lFork2, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(hFork1->getEvent(), hFork1, mUuid);
		expectedOrder.push_back(hFork1);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.removeContext(lFork1, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(hFork2->getEvent(), hFork2, mUuid);
		expectedOrder.push_back(hFork2);
		expectedOrder.push_back(lFork2);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		auto lFork3 = this->addFork(lowPriority);
		auto hFork3 = this->addFork(highPriority);
		mInjector.removeContext(lFork3, mUuid);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(hFork3->getEvent(), hFork3, mUuid);
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
			mInjector.injectRequestEvent(nonUrgentList[i]->getEvent(), nonUrgentList[i], mUuid);
			mInjector.injectRequestEvent(urgentList[i]->getEvent(), urgentList[i], mUuid);
			mInjector.injectRequestEvent(normalList[i]->getEvent(), normalList[i], mUuid);
			mInjector.injectRequestEvent(emergencyList[i]->getEvent(), emergencyList[i], mUuid);
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

		mInjector.injectRequestEvent(emergencyFork2->getEvent(), emergencyFork2, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});
		mInjector.injectRequestEvent(urgentFork->getEvent(), urgentFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});
		mInjector.injectRequestEvent(normalFork->getEvent(), normalFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});
		mInjector.injectRequestEvent(nonUrgentFork->getEvent(), nonUrgentFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});

		mInjector.removeContext(emergencyFork1, mUuid);
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

		mInjector.injectRequestEvent(nonUrgentFork->getEvent(), nonUrgentFork, "BAD_UUID");
		// This should not happen, but we prefer to send in wrong order than not at all.
		expectedOrder.push_back(nonUrgentFork);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		mInjector.injectRequestEvent(nonUrgentFork->getEvent(), nonUrgentFork, mUuid);
		expectedOrder.push_back(nonUrgentFork);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);
		// Injected while not in the list anymore, this should not happen, but we prefer to send in wrong order than not
		// at all.
		mInjector.injectRequestEvent(nonUrgentFork->getEvent(), nonUrgentFork, mUuid);
		expectedOrder.push_back(nonUrgentFork);
		ASSERT_CURRENT_INJECT_ORDER(expectedOrder);

		// No crash double remove
		mInjector.removeContext(nonUrgentFork2, mUuid);
		mInjector.removeContext(nonUrgentFork2, mUuid);

		// List is still usable
		auto nonUrgentFork3 = this->addFork(sofiasip::MsgSipPriority::NonUrgent);
		mInjector.injectRequestEvent(nonUrgentFork3->getEvent(), nonUrgentFork3, mUuid);
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

		mInjector.injectRequestEvent(emergencyFork2->getEvent(), emergencyFork2, mUuid);
		mInjector.injectRequestEvent(normalFork->getEvent(), normalFork, mUuid);
		ASSERT_CURRENT_INJECT_ORDER({});

		this_thread::sleep_for(50ms);

		mInjector.injectRequestEvent(nonUrgentFork->getEvent(), nonUrgentFork, mUuid);
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
	static test_suite_t scheduleInjectorSuite = {"Schedule injector suite",        nullptr, nullptr, nullptr, nullptr,
	                                             sizeof(tests) / sizeof(tests[0]), tests};
	bc_tester_add_suite(&scheduleInjectorSuite);
	return nullptr;
}();

} // namespace schedule_injector_suite
} // namespace tester
} // namespace flexisip
