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

#include <memory>
#include <string>

#include "bctoolbox/logging.h"
#include "bctoolbox/tester.h"
#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/utils/sip-uri.hh"
#include "linphone++/linphone.hh"
#include "registrar/record.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "sofia-wrapper/nta-outgoing-transaction.hh"
#include "sofia-wrapper/sip-header-private.hh"
#include "tester.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/contact-inserter.hh"
#include "utils/core-assert.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/regevent-server.hh"
#include "utils/server/test-conference-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;
using namespace std::string_literals;

namespace flexisip::tester {

class StubListener : public ContactUpdateListener {
public:
	void onRecordFound(const shared_ptr<Record>&) override {
	}
	void onError(const SipStatus&) override {
	}
	void onInvalid(const SipStatus&) override {
	}
	void onContactUpdated(const shared_ptr<ExtendedContact>&) override {
	}
};

// Check that a SUBSCRIBE without an Event header leads to Bad request
void badSubscriptionRequest() {
	Server proxy{{
	    {"module::RegEvent/enabled", "true"},
	}};
	proxy.start();

	stringstream request{};
	request << "SUBSCRIBE sip:service@example.org SIP/2.0\r\n"
	        << "From: <sip:me@example.org>;tag=4687829\r\n"
	        << "To: <sip:service@example.org>\r\n"
	        << "Call-ID: stub-id\r\n"
	        << "CSeq: 20 SUBSCRIBE\r\n";

	NtaAgent client{proxy.getRoot(), "sip:127.0.0.1:0"};
	auto transaction = client.createOutgoingTransaction(request.str(), "sip:127.0.0.1:"s + proxy.getFirstPort());

	CoreAssert{proxy}.iterateUpTo(5, [&transaction] { return transaction->isCompleted(); }, 1s).assert_passed();
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 400);
}

void basicSubscription() {
	const string confFactoryUri{"sip:conference-factory@sip.example.org"};
	Server proxy{{
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::RegEvent/enabled", "true"},
	    {"module::DoSProtection/enabled", "false"},
	    {"module::Registrar/reg-domains", "sip.example.org"},
	    {"module::Registrar/enable-gruu", "true"},

	    {"conference-server/database-backend", "sqlite"},
	    {"conference-server/database-connection-string", ":memory:"},
	    {"conference-server/conference-factory-uris", confFactoryUri},
	    // Registrars / Local confs
	    {"conference-server/local-domains", "sip.example.org 127.0.0.1"},
	    {"conference-server/state-directory", bcTesterWriteDir().append("var/lib/flexisip")},
	}};

	const auto& agent = *proxy.getAgent();
	const auto& registrarDb = proxy.getRegistrarDb();
	const auto& confMan = proxy.getConfigManager();

	RegEventServer regEvent{registrarDb};
	proxy.setConfigParameter({"module::RegEvent/regevent-server", regEvent.getTransport().str()});
	proxy.start();

	// Update conference server configuration with proxy information.
	confMan->getRoot()
	    ->get<GenericStruct>("conference-server")
	    ->get<ConfigValue>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");

	const auto client = ClientBuilder(agent).setConferenceFactoryUri(confFactoryUri).build("sip:test@sip.example.org");

	TestConferenceServer conferenceServer(agent, proxy.getConfigManager(), proxy.getRegistrarDb());

	const string participantFrom{"sip:participant1@localhost"};
	const Record::Key participantTopic{SipUri(participantFrom), registrarDb->useGlobalDomain()};
	const auto participantAddress = linphone::Factory::get()->createAddress(participantFrom);
	const string otherParticipantFrom{"sip:participant2@localhost"};
	const Record::Key otherParticipantTopic{SipUri(otherParticipantFrom), registrarDb->useGlobalDomain()};

	// Fill the Registrar DB with participants.
	ContactInserter inserter{*registrarDb, make_shared<AcceptUpdatesListener>()};
	inserter.withGruu(true)
	    .setExpire(1000s)
	    .setContactParams({R"(+org.linphone.specs="ephemeral/1.1,groupchat/1.2,lime")"})
	    .setAor(participantFrom)
	    .insert({.uniqueId = "device-a"})
	    .setAor(otherParticipantFrom)
	    .insert({.uniqueId = "device-b"})
	    .insert({.uniqueId = "device-c"});

	const auto chatRoom = client.chatroomBuilder()
	                          .setSubject("reg-event-test")
	                          .build({
	                              participantAddress,
	                              linphone::Factory::get()->createAddress(otherParticipantFrom),
	                          });

	const auto getDevicesCountInChatroom = [&chatRoom]() {
		size_t count = 0;
		for (const auto& participant : chatRoom->getParticipants()) {
			count += participant->getDevices().size();
		}
		return count;
	};

	CoreAssert asserter{client, regEvent.getCore(), agent};
	asserter
	    .iterateUpTo(0x20, [&getDevicesCountInChatroom] { return LOOP_ASSERTION(getDevicesCountInChatroom() >= 3); })
	    .assert_passed();

	{
		const auto participants = chatRoom->getParticipants();
		BC_HARD_ASSERT_CPP_EQUAL(participants.size(), 2);
		const auto& firstParticipant = participants.front();
		BC_ASSERT_CPP_EQUAL(firstParticipant->getAddress()->asString(), participantFrom);
		BC_ASSERT_CPP_EQUAL(firstParticipant->getDevices().size(), 1);
		const auto& secondParticipant = participants.back();
		BC_ASSERT_CPP_EQUAL(secondParticipant->getAddress()->asString(), otherParticipantFrom);
		BC_ASSERT_CPP_EQUAL(secondParticipant->getDevices().size(), 2);
	}

	// Let's add a new device.
	inserter.insert({.uniqueId = "device-d"});
	registrarDb->publish(otherParticipantTopic, "");
	asserter
	    .iterateUpTo(
	        7, [&getDevicesCountInChatroom] { return LOOP_ASSERTION(4 <= getDevicesCountInChatroom()); }, 1s)
	    .assert_passed();

	{
		const auto participants = chatRoom->getParticipants();
		const auto& secondParticipantDevices = participants.back()->getDevices();
		BC_ASSERT_CPP_EQUAL(secondParticipantDevices.size(), 3);
		BC_ASSERT_CPP_EQUAL(secondParticipantDevices.back()->getAddress()->getUriParam("gr"), "device-d");
	}

	// Remove a device.
	inserter.setExpire(0s).insert({.uniqueId = "device-d"});
	registrarDb->publish(otherParticipantTopic, "");
	asserter
	    .iterateUpTo(
	        10, [&getDevicesCountInChatroom] { return LOOP_ASSERTION(getDevicesCountInChatroom() == 3); }, 1s)
	    .assert_passed();

	{
		const auto participants = chatRoom->getParticipants();
		const auto& secondParticipantDevices = participants.back()->getDevices();
		BC_ASSERT_CPP_EQUAL(secondParticipantDevices.size(), 2);
		BC_ASSERT_CPP_NOT_EQUAL(secondParticipantDevices.back()->getAddress()->getUriParam("gr"), "device-d");
	}

	// Remove the last device of a participant.
	registrarDb->clear(SipUri(participantFrom), "stub-callid", make_shared<StubListener>());
	registrarDb->publish(participantTopic, "");
	asserter.iterateUpTo(3, [&getDevicesCountInChatroom] { return LOOP_ASSERTION(getDevicesCountInChatroom() == 2); })
	    .assert_passed();

	{
		const auto participants = chatRoom->getParticipants();
		BC_HARD_ASSERT_CPP_EQUAL(participants.size(), 2);
		const auto& firstParticipant = *participants.front();
		BC_ASSERT_CPP_EQUAL(firstParticipant.getAddress()->asString(), participantFrom);
		BC_ASSERT_CPP_EQUAL(firstParticipant.getDevices().size(), 0);
	}

	// Remove participant from chatroom, check that corresponding topic is unsubscribed on the "remote" Register.
	const auto& onRegisterListeners = registrarDb->getOnContactRegisteredListeners();
	BC_ASSERT_TRUE(onRegisterListeners.find(participantTopic.asString()) != onRegisterListeners.end());
	chatRoom->removeParticipant(chatRoom->findParticipant(participantAddress));
	asserter
	    .iterateUpTo(3,
	                 [&registrarDb, &participantTopic, &onRegisterListeners] {
		                 // Trigger registrarDb listeners cleanup.
		                 registrarDb->publish(participantTopic, "");
		                 FAIL_IF(onRegisterListeners.find(participantTopic.asString()) != onRegisterListeners.end());
		                 return ASSERTION_PASSED();
	                 })
	    .assert_passed();

	// Reroute everything locally on the Conference Server.
	conferenceServer.clearLocalDomainList();

	// Add a new participant.
	const string participantRebindFrom{"sip:participant_re_bind@localhost"};
	inserter.setExpire(10s).setAor(participantRebindFrom).insert({.uniqueId = "re-device-a"});
	chatRoom->addParticipant(linphone::Factory::get()->createAddress(participantRebindFrom));
	asserter.iterateUpTo(8, [&getDevicesCountInChatroom] { return LOOP_ASSERTION(getDevicesCountInChatroom() == 3); })
	    .assert_passed();

	// Check if the participant was still added (locally).
	const auto participants = chatRoom->getParticipants();
	BC_ASSERT_CPP_EQUAL(participants.size(), 2);
	const auto& newParticipant = *participants.back();
	BC_ASSERT_CPP_EQUAL(newParticipant.getAddress()->asString(), participantRebindFrom);
	BC_ASSERT_CPP_EQUAL(newParticipant.getDevices().size(), 1);
}

/**
 * Tool for simulating a subscriber to a topic in the registrarDb.
 */
struct Subscriber {
	explicit Subscriber(const SipUri& aor, nta_message_f* onResponse, Random::StringGenerator& rsg)
	    : mSuRoot(make_shared<sofiasip::SuRoot>()), mClient(mSuRoot,
	                                                        "sip:" + aor.getUser() + "@127.0.0.1:0;transport=tcp",
	                                                        onResponse,
	                                                        reinterpret_cast<nta_agent_magic_t*>(this)),
	      mAor(aor.str()), mUri("sip:" + aor.getUser() + "@127.0.0.1:" + mClient.getFirstPort() + ";transport=tcp"),
	      mCallId(rsg.generate(10)), mFromTag(rsg.generate(10)), mTotalNotifyReceived(0), mToHeader(), mEvent("reg"),
	      mAccept("application/reginfo+xml") {
	}

	shared_ptr<sofiasip::NtaOutgoingTransaction> subscribe(string_view to, string_view destUri) {
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_subscribe, to);
		request->makeAndInsert<SipHeaderFrom>(mAor, mFromTag);
		request->makeAndInsert<SipHeaderTo>(to);
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_subscribe);
		request->insertHeader(SipHeaderCallID{mCallId});
		request->makeAndInsert<SipHeaderMaxForwards>(70u);
		request->makeAndInsert<SipHeaderEvent>(mEvent);
		request->makeAndInsert<SipHeaderExpires>(10);
		request->makeAndInsert<SipHeaderContact>("<"s + mUri + ">");
		request->makeAndInsert<SipHeaderUserAgent>("NtaAgent-for-Flexisip-regression-tests");
		request->makeAndInsert<SipHeaderAccept>(mAccept);
		return mClient.createOutgoingTransaction(std::move(request), destUri);
	}

	shared_ptr<sofiasip::NtaOutgoingTransaction> unsubscribe(string_view to, string_view destUri) {
		auto request = make_unique<MsgSip>();
		request->makeAndInsert<SipHeaderRequest>(sip_method_subscribe, to);
		request->makeAndInsert<SipHeaderFrom>(mAor, mFromTag);
		request->makeAndInsert<SipHeaderTo>(mToHeader);
		request->makeAndInsert<SipHeaderCSeq>(20u, sip_method_subscribe);
		request->insertHeader(SipHeaderCallID{mCallId});
		request->makeAndInsert<SipHeaderMaxForwards>(70u);
		request->makeAndInsert<SipHeaderEvent>(mEvent);
		request->makeAndInsert<SipHeaderExpires>(0);
		request->makeAndInsert<SipHeaderContact>("<"s + mUri + ">");
		request->makeAndInsert<SipHeaderUserAgent>("NtaAgent-for-Flexisip-regression-tests");
		request->makeAndInsert<SipHeaderAccept>(mAccept);
		return mClient.createOutgoingTransaction(std::move(request), destUri);
	}

	shared_ptr<sofiasip::SuRoot> mSuRoot;
	NtaAgent mClient;
	string mAor;
	string mUri;
	SipHeaderCallID mCallId;
	string mFromTag;
	int mTotalNotifyReceived;
	string mToHeader;
	string mEvent;
	string mAccept;
};

void wrongEventHeaderInSubscribeRequest() {
	auto random = tester::random::random();
	auto rsg = random.string();

	const auto suRoot = make_shared<sofiasip::SuRoot>();
	const auto configuration = make_shared<ConfigManager>();
	const auto registrarDb = make_shared<RegistrarDb>(suRoot, configuration);

	const string aorOfInterest{"sip:aor-of-interest@sip.example.org"};
	const auto topic = Record::Key{SipUri{aorOfInterest}, registrarDb->useGlobalDomain()};

	RegEventServer regEvent{registrarDb};

	Subscriber subscriber{SipUri{"sip:subscriber@sip.example.org"}, nullptr, rsg};
	subscriber.mEvent = "wrong-event";
	const auto subscriptionFromSubscriber = subscriber.subscribe(aorOfInterest, regEvent.getTransport().str());

	CoreAssert{regEvent.getCore(), suRoot, subscriber.mSuRoot}
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(!subscriptionFromSubscriber->isCompleted());
		        FAIL_IF(subscriptionFromSubscriber->getStatus() != 489);
		        FAIL_IF(subscriber.mTotalNotifyReceived != 0);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

void wrongAcceptHeaderInSubscribeRequest() {
	auto random = tester::random::random();
	auto rsg = random.string();

	const auto suRoot = make_shared<sofiasip::SuRoot>();
	const auto configuration = make_shared<ConfigManager>();
	const auto registrarDb = make_shared<RegistrarDb>(suRoot, configuration);

	const string aorOfInterest{"sip:aor-of-interest@sip.example.org"};
	const auto topic = Record::Key{SipUri{aorOfInterest}, registrarDb->useGlobalDomain()};

	RegEventServer regEvent{registrarDb};

	Subscriber subscriber{SipUri{"sip:subscriber@sip.example.org"}, nullptr, rsg};
	subscriber.mAccept = "wrong-accept";
	const auto subscriptionFromSubscriber = subscriber.subscribe(aorOfInterest, regEvent.getTransport().str());

	CoreAssert{regEvent.getCore(), suRoot, subscriber.mSuRoot}
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(!subscriptionFromSubscriber->isCompleted());
		        FAIL_IF(subscriptionFromSubscriber->getStatus() != 488);
		        FAIL_IF(subscriber.mTotalNotifyReceived != 0);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

/**
 * Test NOTIFY requests receipt when two subscribers are subscribing to the same topic.
 */
void multipleSubscribersToOneRecordKey() {
	auto random = tester::random::random();
	auto rsg = random.string();

	const auto suRoot = make_shared<sofiasip::SuRoot>();
	const auto configuration = make_shared<ConfigManager>();
	const auto registrarDb = make_shared<RegistrarDb>(suRoot, configuration);

	const string aorOfInterest{"sip:aor-of-interest@sip.example.org"};
	const auto topic = Record::Key{SipUri{aorOfInterest}, registrarDb->useGlobalDomain()};

	// Fill the Registrar DB with a topic ('AOR of interest').
	ContactInserter inserter{*registrarDb, make_shared<AcceptUpdatesListener>()};
	const auto deviceId = rsg.generate(25);
	inserter.withGruu(true).setExpire(10s).setAor(aorOfInterest).insert({.uniqueId = deviceId});

	RegEventServer regEvent{registrarDb};
	const auto regEventUri = regEvent.getTransport().str();

	const auto onSubscriberResponse = [](nta_agent_magic_t* magic, nta_agent_t* agent, msg_t* msg, sip_t* sip) {
		auto* subscriber = reinterpret_cast<Subscriber*>(magic);

		if (sip->sip_request and sip->sip_request->rq_method == sip_method_notify) subscriber->mTotalNotifyReceived++;

		if (subscriber->mToHeader.empty()) {
			sofiasip::Home home{};
			subscriber->mToHeader =
			    "<"s + url_as_string(home.home(), sip->sip_from->a_url) + ">;tag=" + sip->sip_from->a_tag;
		}

		nta_msg_treply(agent, msg, 200, "Notification received", TAG_END());
		return 0;
	};

	Subscriber subscriber{SipUri{"sip:subscriber@sip.example.org"}, onSubscriberResponse, rsg};
	const auto subscriptionFromSubscriber = subscriber.subscribe(aorOfInterest, regEventUri);
	Subscriber otherSubscriber{SipUri{"sip:other-subscriber@sip.example.org"}, onSubscriberResponse, rsg};
	const auto subscriptionFromOtherSubscriber = otherSubscriber.subscribe(aorOfInterest, regEventUri);

	CoreAssert asserter{regEvent.getCore(), suRoot, subscriber.mSuRoot, otherSubscriber.mSuRoot};
	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(!subscriptionFromSubscriber->isCompleted());
		        FAIL_IF(subscriptionFromSubscriber->getStatus() != 200);
		        FAIL_IF(subscriber.mTotalNotifyReceived != 1);
		        FAIL_IF(!subscriptionFromOtherSubscriber->isCompleted());
		        FAIL_IF(subscriptionFromOtherSubscriber->getStatus() != 200);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 1);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Add a new device to 'AOR of interest'.
	const auto newDeviceId = rsg.generate(25);
	inserter.insert({.uniqueId = newDeviceId});
	registrarDb->publish(topic, "");

	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(subscriber.mTotalNotifyReceived != 2);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 2);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Replace subscription from 'subscriber' to topic.
	const auto newSubscriptionFromSubscriber = subscriber.subscribe(aorOfInterest, regEventUri);

	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(!newSubscriptionFromSubscriber->isCompleted());
		        FAIL_IF(newSubscriptionFromSubscriber->getStatus() != 200);
		        FAIL_IF(subscriber.mTotalNotifyReceived != 3);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 2);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Unsubscribe 'subscriber' from topic.
	const auto unsubscriptionFromSubscriber = subscriber.unsubscribe(aorOfInterest, regEventUri);

	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(!unsubscriptionFromSubscriber->isCompleted());
		        FAIL_IF(unsubscriptionFromSubscriber->getStatus() != 200);
		        FAIL_IF(subscriber.mTotalNotifyReceived != 3);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 2);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Remove a device from 'AOR of interest'.
	inserter.setExpire(0s).insert({.uniqueId = newDeviceId});
	registrarDb->publish(topic, "");

	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(subscriber.mTotalNotifyReceived != 3);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 3);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Unsubscribe 'other-subscriber' from topic.
	const auto unsubscriptionFromOtherSubscriber = otherSubscriber.unsubscribe(aorOfInterest, regEventUri);

	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(subscriber.mTotalNotifyReceived != 3);
		        FAIL_IF(!unsubscriptionFromOtherSubscriber->isCompleted());
		        FAIL_IF(unsubscriptionFromOtherSubscriber->getStatus() != 200);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 3);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .hard_assert_passed();

	// Remove last device of 'AOR of interest'.
	inserter.setExpire(0s).insert({.uniqueId = deviceId});
	registrarDb->publish(topic, "");

	asserter
	    .iterateUpTo(
	        32,
	        [&]() {
		        FAIL_IF(subscriber.mTotalNotifyReceived != 3);
		        FAIL_IF(otherSubscriber.mTotalNotifyReceived != 3);
		        return ASSERTION_PASSED();
	        },
	        2s)
	    .assert_passed();
}

namespace {

TestSuite _("regevent",
            {
                CLASSY_TEST(badSubscriptionRequest),
                CLASSY_TEST(basicSubscription),
                CLASSY_TEST(wrongEventHeaderInSubscribeRequest),
                CLASSY_TEST(wrongAcceptHeaderInSubscribeRequest),
                CLASSY_TEST(multipleSubscribersToOneRecordKey),
            });

}

} // namespace flexisip::tester