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

#include "bctoolbox/tester.h"
#include "registrar/record.hh"
#include "registration-events/server.hh"

#include <bctoolbox/logging.h>

#include <memory>
#include <string>

#include "flexisip/utils/sip-uri.hh"
#include "linphone/misc.h"
#include <linphone++/linphone.hh>

#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"

#include "agent.hh"
#include "registrar/registrar-db.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/contact-inserter.hh"
#include "utils/core-assert.hh"
#include "utils/proxy-server.hh"
#include "utils/test-conference-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace linphone;

namespace flexisip {
namespace tester {

class StubListener : public ContactUpdateListener {
public:
	void onRecordFound(const shared_ptr<Record>&) override {
	}
	void onError(const SipStatus&) override {
	}
	void onInvalid(const SipStatus&) override {
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
	}
};

void basicSubscription() {
	// Agent initialisation
	const string confFactoryUri = "sip:conference-factory@sip.example.org";
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0"},
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
	// RegEvent Server
	const auto linFactory = Factory::get();
	const auto regEventCore = tester::minimalCore(*linFactory);
	{
		const auto& transports = regEventCore->getTransports();
		transports->setTcpPort(LC_SIP_TRANSPORT_RANDOM);
		regEventCore->setTransports(transports);
	}
	regEventCore->addListener(make_shared<flexisip::RegistrationEvent::Server::Subscriptions>(proxy.getRegistrarDb()));
	regEventCore->start();
	auto* configRoot = proxy.getConfigManager()->getRoot();
	configRoot->get<GenericStruct>("module::RegEvent")
	    ->get<ConfigValue>("regevent-server")
	    ->set("sip:127.0.0.1:"s + std::to_string(regEventCore->getTransportsUsed()->getTcpPort()) + ";transport=tcp");
	proxy.start();
	configRoot->get<GenericStruct>("conference-server")
	    ->get<ConfigValue>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");
	// Client initialisation
	const auto client =
	    ClientBuilder(*proxy.getAgent()).setConferenceFactoryUri(confFactoryUri).build("sip:test@sip.example.org");
	const auto& agent = *proxy.getAgent();
	// Conference Server
	TestConferenceServer conferenceServer(agent, proxy.getConfigManager(), proxy.getRegistrarDb());
	auto& regDb = proxy.getAgent()->getRegistrarDb();
	ContactInserter inserter{regDb, std::make_shared<AcceptUpdatesListener>()};
	const string participantFrom = "sip:participant1@localhost";
	const Record::Key participantTopic{SipUri(participantFrom), regDb.useGlobalDomain()};
	const auto participantAddress = linFactory->createAddress(participantFrom);
	const string otherParticipantFrom = "sip:participant2@localhost";
	const Record::Key otherParticipantTopic{SipUri(otherParticipantFrom), regDb.useGlobalDomain()};
	// Fill the Regisrar DB with participants
	inserter.withGruu(true)
	    .setExpire(1000s)
	    .setContactParams({R"(+org.linphone.specs="ephemeral/1.1,groupchat/1.2,lime")"})
	    .setAor(participantFrom)
	    .insert({.uniqueId = "ubuntu"})
	    .setAor(otherParticipantFrom)
	    .insert({.uniqueId = "redhat"})
	    .insert({.uniqueId = "debian"});

	const auto chatRoom = client.chatroomBuilder()
	                          .setSubject("reg-event-test")
	                          .build({participantAddress, linFactory->createAddress(otherParticipantFrom)});
	const auto totalDevicesCount = [&chatRoom]() {
		auto count = 0;
		for (const auto& participant : chatRoom->getParticipants()) {
			count += participant->getDevices().size();
		}
		return count;
	};
	CoreAssert asserter{client, regEventCore, agent};

	BC_ASSERT_TRUE(asserter.iterateUpTo(13, [&totalDevicesCount] { return 3 <= totalDevicesCount(); }));

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

	// Let's add a new device
	inserter.insert({.uniqueId = "new-device"});
	regDb.publish(otherParticipantTopic, "");
	BC_ASSERT_TRUE(asserter.iterateUpTo(7, [&totalDevicesCount] { return 4 <= totalDevicesCount(); }, 1s));

	{
		const auto participants = chatRoom->getParticipants();
		const auto& secondParticipantDevices = participants.back()->getDevices();
		BC_ASSERT_CPP_EQUAL(secondParticipantDevices.size(), 3);
		BC_ASSERT_CPP_EQUAL(secondParticipantDevices.back()->getAddress()->getUriParam("gr"), "new-device");
	}

	// Remove a device
	inserter.setExpire(0s).insert({.uniqueId = "new-device"});
	regDb.publish(otherParticipantTopic, "");
	BC_ASSERT_TRUE(asserter.iterateUpTo(10, [&totalDevicesCount] { return totalDevicesCount() == 3; }, 1s));

	{
		const auto participants = chatRoom->getParticipants();
		const auto& secondParticipantDevices = participants.back()->getDevices();
		BC_ASSERT_CPP_EQUAL(secondParticipantDevices.size(), 2);
		BC_ASSERT_CPP_NOT_EQUAL(secondParticipantDevices.back()->getAddress()->getUriParam("gr"), "new-device");
	}

	// Remove the last device of a participant
	regDb.clear(SipUri(participantFrom), "stub-callid", make_shared<StubListener>());
	regDb.publish(participantTopic, "");
	BC_ASSERT_TRUE(asserter.iterateUpTo(3, [&totalDevicesCount] { return totalDevicesCount() == 2; }));

	{
		const auto participants = chatRoom->getParticipants();
		BC_HARD_ASSERT_CPP_EQUAL(participants.size(), 2);
		const auto& firstParticipant = *participants.front();
		BC_ASSERT_CPP_EQUAL(firstParticipant.getAddress()->asString(), participantFrom);
		BC_ASSERT_CPP_EQUAL(firstParticipant.getDevices().size(), 0);
	}

	// Remove participant from chatroom, check that corresponding topic is unsubbed on the "remote" Register
	const auto& onRegisterListeners = regDb.getOnContactRegisteredListeners();
	BC_ASSERT_TRUE(onRegisterListeners.find(participantTopic.asString()) != onRegisterListeners.end());
	chatRoom->removeParticipant(chatRoom->findParticipant(participantAddress));
	BC_ASSERT_TRUE(asserter.iterateUpTo(3, [&regDb, &participantTopic, &onRegisterListeners] {
		// Trigger regDb listeners cleanup
		regDb.publish(participantTopic, "");
		return onRegisterListeners.find(participantTopic.asString()) == onRegisterListeners.end();
	}));

	// Reroute everything locally on the Conference Server
	conferenceServer.clearLocalDomainList();

	// Add a new participant
	const string participantRebindFrom = "sip:participant_re_bind@localhost";
	inserter.setExpire(10s).setAor(participantRebindFrom).insert({.uniqueId = "re-ubuntu"});
	chatRoom->addParticipant(linFactory->createAddress(participantRebindFrom));
	BC_ASSERT_TRUE(asserter.iterateUpTo(8, [&totalDevicesCount] { return totalDevicesCount() == 3; }));

	// Check if the participant was still added (locally)
	const auto participants = chatRoom->getParticipants();
	BC_ASSERT_CPP_EQUAL(participants.size(), 2);
	const auto& newParticipant = *participants.back();
	BC_ASSERT_CPP_EQUAL(newParticipant.getAddress()->asString(), participantRebindFrom);
	BC_ASSERT_CPP_EQUAL(newParticipant.getDevices().size(), 1);
}

namespace {
TestSuite _("Registration Event",
            {
                CLASSY_TEST(basicSubscription),
            });
}
} // namespace tester
} // namespace flexisip
