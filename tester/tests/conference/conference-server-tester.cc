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

#include <chrono>
#include <initializer_list>
#include <memory>
#include <vector>

#include "flexisip/registrar/registar-listeners.hh"

#include "conference/conference-server.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "registrardb-internal.hh"
#include "registrardb-redis.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/server/mysql-server.hh"
#include "utils/server/proxy-server.hh"
#include "utils/server/redis-server.hh"
#include "utils/server/test-conference-server.hh"
#include "utils/string-utils.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

namespace {

class AllJoinedWaiter : public linphone::ChatRoomListener, public std::enable_shared_from_this<AllJoinedWaiter> {
public:
	void onConferenceJoined(const std::shared_ptr<linphone::ChatRoom>& chatRoom,
	                        const std::shared_ptr<const linphone::EventLog>&) override {
		for (auto it = mChatrooms.begin(); it != mChatrooms.end(); ++it) {
			if (*it == chatRoom->cPtr()) {
				mChatrooms.erase(it);
				break;
			}
		}
	}

	void setChatrooms(std::initializer_list<shared_ptr<linphone::ChatRoom>>&& chatrooms) {
		mChatrooms.reserve(chatrooms.size());
		auto self = shared_from_this();
		for (const auto& chatroom : chatrooms) {
			chatroom->addListener(self);
			mChatrooms.emplace_back(chatroom->cPtr());
		}
	}

	const auto& getChatrooms() {
		return mChatrooms;
	}

private:
	std::vector<const void*> mChatrooms{};
};

/**
 * Test that the conference-server correctly binds the chat rooms from the chat rooms DB into the registrar DB
 * during its initialization.
 */
void conferenceServerBindsChatroomsFromDBOnInit() {
	const MysqlServer mysqlServer{};
	const string confFactoryUri = "sip:conference-factory@sip.example.org";
	const string confFocusUri = "sip:conference-focus@sip.example.org";
	Server proxy{{// Requesting bind on port 0 to let the kernel find any available port
	              {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	              {"module::Registrar/enabled", "true"},
	              {"module::Registrar/reg-domains", "sip.example.org"},

	              // `mysql` to be as close to real-world deployments as possible
	              {"conference-server/database-backend", "mysql"},
	              {"conference-server/database-connection-string", mysqlServer.connectionString()},
	              {"conference-server/conference-factory-uris", confFactoryUri},
	              {"conference-server/conference-focus-uris", confFocusUri},
	              {"conference-server/empty-chat-room-deletion", "false"},
	              {"conference-server/state-directory", bcTesterWriteDir().append("var/lib/flexisip")}}};
	proxy.start();
	const auto& regDb = proxy.getRegistrarDb();
	const auto* registrarBackend = dynamic_cast<const RegistrarDbInternal*>(&regDb->getRegistrarBackend());
	BC_HARD_ASSERT_TRUE(registrarBackend != nullptr);
	const auto& records = registrarBackend->getAllRecords();
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 0);
	const auto& agent = *proxy.getAgent();
	ClientBuilder clientBuilder{agent};
	clientBuilder.setConferenceFactoryAddress(linphone::Factory::get()->createAddress(confFactoryUri))
	    .setLimeX3DH(OnOff::Off);
	const auto me = clientBuilder.build("I@sip.example.org");
	const auto you = clientBuilder.build("you@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 2);
	CoreAssert asserter{proxy, you, me};
	auto chatroomBuilder = me.chatroomBuilder();
	chatroomBuilder.setBackend(linphone::ChatRoom::Backend::FlexisipChat).setGroup(OnOff::On);
	const auto listener = make_shared<AllJoinedWaiter>();
	const auto& confMan = proxy.getConfigManager();
	const auto conferenceServerUri = [confServerCfg = confMan->getRoot()->get<GenericStruct>("conference-server")] {
		return confServerCfg->get<ConfigString>("transport")->read();
	};
	{ // Populate conference server's DB
		mysqlServer.waitReady();
		const TestConferenceServer conferenceServer(agent, confMan, regDb);
		BC_HARD_ASSERT_CPP_EQUAL(records.size(), 2 /* users */ + 1 /* factory */ + 1 /* focus */);
		const auto& inMyRoom = you.getMe();
		listener->setChatrooms({
		    chatroomBuilder.setSubject("Boom0").build({inMyRoom}),
		    chatroomBuilder.setSubject("Boom1").build({inMyRoom}),
		    chatroomBuilder.setSubject("Boom2").build({inMyRoom}),
		    chatroomBuilder.setSubject("Boom3").build({inMyRoom}),
		});

		asserter
		    .iterateUpTo(8,
		                 [&chatrooms = listener->getChatrooms()] {
			                 FAIL_IF(0 < chatrooms.size());
			                 return ASSERTION_PASSED();
		                 })
		    .assert_passed();

		BC_ASSERT_CPP_EQUAL(listener->getChatrooms().size(), 0);
		// Chat rooms are now only identified by the parameter conf-id therefore the registrarDb doesn't grow anymore
		BC_ASSERT_CPP_EQUAL(records.size(), 2 /* users */ + 1 /* factory */ + 1 /* focus */);
	} // Shutdown conference server
	(const_cast<RegistrarDbInternal*>(registrarBackend))->clearAll();

	// Spin it up again
	const TestConferenceServer conferenceServer(agent, confMan, regDb);

	// The conference server restored its chatrooms from DB and bound them back on the Registrar
	// Chat rooms are now only identified by the parameter conf-id therefore the registrarDb doesn't grow anymore
	BC_ASSERT_CPP_EQUAL(records.size(), 1 /* factory */ + 1 /* focus */);
	for (const auto& record : records) {
		const auto& contacts = record.second->getExtendedContacts();
		BC_ASSERT_CPP_EQUAL(contacts.size(), 1);
		BC_ASSERT_CPP_EQUAL(contacts.latest()->get()->urlAsString(), conferenceServerUri());
	}
}

// Anchor CNFFACREGKEYMIG
// Flexisip 2.2 used CallIDs as keys in the Registrar in the absence of a +sip.instance field. The Conference server
// relied on this to update its contact in the registrar, and now relies on a +sip.instance to achieve the same result.
// Unfortunately, the transition from 2.2 to 2.3 leaves an entry with the "CONFERENCE" CallID as key that the conference
// server has to clean up manually.
void conferenceServerClearsOldBindingsOnInit() {
	const string confFactoryUri = "sip:conference-factory@sip.example.org";
	const string confFocusUri = "sip:conference-focus@sip.example.org";
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},

	    {"conference-server/database-backend", "sqlite"},
	    {"conference-server/database-connection-string", "/dev/null"},
	    {"conference-server/conference-factory-uris", confFactoryUri},
	    {"conference-server/conference-focus-uris", confFocusUri},
	    {"conference-server/state-directory", bcTesterWriteDir().append("var/lib/flexisip")},
	}};
	proxy.start();
	auto& registrar = *proxy.getRegistrarDb();
	const auto* registrarBackend = dynamic_cast<const RegistrarDbInternal*>(&registrar.getRegistrarBackend());
	BC_HARD_ASSERT_TRUE(registrarBackend != nullptr);
	const auto& records = registrarBackend->getAllRecords();
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 0);
	sofiasip::Home home{};
	const SipUri aor(confFactoryUri);
	BindingParameters params{};
	params.globalExpire = 0xdead;
	params.callId = "CONFERENCE";
	const auto unexpectedContact = "sip:unexpected@127.0.0.1";
	const auto contact =
	    sip_contact_create(home.home(), reinterpret_cast<const url_string_t*>(unexpectedContact), nullptr);
	// Fake an existing contact as if left over from a previous version
	registrar.bind(aor, contact, params, nullptr);
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 1);
	{
		const auto& contacts = records.begin()->second->getExtendedContacts();
		BC_HARD_ASSERT_CPP_EQUAL(contacts.size(), 1);
		BC_ASSERT_CPP_EQUAL(contacts.latest()->get()->urlAsString(), unexpectedContact);
	}

	const TestConferenceServer conferenceServer(proxy);

	BC_ASSERT_CPP_EQUAL(records.size(), 1 /* factory */ + 1 /* focus */);
	const auto& contacts = records.begin()->second->getExtendedContacts();
	BC_ASSERT_CPP_EQUAL(contacts.size(), 1);
	for (const auto& contact : contacts) {
		// Left over contact has been cleaned up
		BC_ASSERT_CPP_NOT_EQUAL(contact->urlAsString(), unexpectedContact);
	}
}

/** Assert the conference server re-sends the INVITE when a participant device comes back online.
 *
 *  1. Set up two participants with one device each, a proxy and a conference server.
 *  2. Simulate a device going offline long enough for its REGISTER to expire (but still being within its message-expire
 * time, such that it is still in the RegistrarDB).
 *  3. Invite it to a chatroom. The conference server will get a 404 from the proxy for this device.
 *  4. Simulate device going back online. The proxy will notify the conference server and the latter will re-send the
 * INVITE to the participant device.
 */
void inviteResentOnReconnect() {
	static const auto confFactoryUri = "sip:conference-factory@sip.example.org"s;
	const auto testDir = TmpDir(__FUNCTION__ + "."s);
	auto proxy = Server({
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},

	    {"conference-server/database-backend", "sqlite"},
	    {"conference-server/database-connection-string", "/dev/null"},
	    {"conference-server/conference-factory-uris", confFactoryUri},
	    {"conference-server/conference-focus-uris", "sip:conference-focus@sip.example.org"},
	    {"conference-server/state-directory", testDir.path() / "conf-server"},
	});
	proxy.start();
	auto& agent = *proxy.getAgent();
	const auto& regDb = proxy.getRegistrarDb();
	auto conferenceServer = TestConferenceServer(agent, proxy.getConfigManager(), regDb);
	auto clientBuilder = ClientBuilder(agent);
	clientBuilder.setConferenceFactoryAddress(linphone::Factory::get()->createAddress(confFactoryUri))
	    .setLimeX3DH(OnOff::Off);
	const auto simon = clientBuilder.build("simon@sip.example.org");
	auto julien = clientBuilder.setMessageExpires(0xbah).build("julien@sip.example.org");
	julien.disconnect(); // Client goes offline
	const auto julienAddress = julien.getMe();
	const auto& registrarBackend = dynamic_cast<const RegistrarDbInternal&>(regDb->getRegistrarBackend());
	auto& records = registrarBackend.getAllRecords();
	BC_HARD_ASSERT(!records.empty());
	const auto& julienKey = Record::Key(SipUri(julienAddress->asStringUriOnly()), false);
	const auto& julienDevices = records.at(julienKey.asString())->getExtendedContacts();
	auto& julienDeviceContact = (**julienDevices.latest());
	constexpr auto margin = 10s;
	const auto inviteExpirationTime = julienDeviceContact.getSipExpires() + margin;
	julienDeviceContact.setRegisterTime(julienDeviceContact.getRegisterTime() - inviteExpirationTime.count());
	// Registration expires, but the contact is still in the Registrar (because of message-expires)
	BC_ASSERT(!julienDeviceContact.isExpired());
	auto asserter = CoreAssert(proxy, julien, simon);
	const auto listener = make_shared<AllJoinedWaiter>();
	const auto simonChatroom = simon.chatroomBuilder()
	                               .setBackend(linphone::ChatRoom::Backend::FlexisipChat)
	                               .setGroup(OnOff::On)
	                               .setSubject("Liblinphone Team")
	                               .build({julienAddress});
	listener->setChatrooms({simonChatroom});
	asserter
	    .iterateUpTo(
	        8, [&chatRoomsToCreate = listener->getChatrooms()] { return LOOP_ASSERTION(chatRoomsToCreate.empty()); })
	    .assert_passed();

	const auto confServerChatrooms = conferenceServer.getChatrooms();
	BC_HARD_ASSERT_CPP_EQUAL(confServerChatrooms.size(), 1);
	auto julienParticipant = shared_ptr<linphone::Participant>();
	for (auto& participant : confServerChatrooms.front()->getParticipants()) {
		if (participant->getAddress()->equal(julienAddress)) {
			julienParticipant = participant;
			break;
		}
	}
	BC_HARD_ASSERT_NOT_NULL(julienParticipant);
	const auto devices = julienParticipant->getDevices();
	BC_HARD_ASSERT_CPP_EQUAL(devices.size(), 1);
	const auto& offlineDevice = devices.front();
	BC_ASSERT_ENUM_EQUAL(offlineDevice->getState(), linphone::ParticipantDevice::State::Joining);

	SLOGD << "TEST " << __FUNCTION__ << " Client reconnects";
	julien.reconnect();
	julien.refreshRegisters();
	asserter
	    .iterateUpTo(
	        8, [&] { return LOOP_ASSERTION(offlineDevice->getState() == linphone::ParticipantDevice::State::Present); })
	    .assert_passed();
	BC_ASSERT_ENUM_EQUAL(offlineDevice->getState(), linphone::ParticipantDevice::State::Present);
}

/**
 * Test that the conference-server correctly binds the "old" chatroom (chatroom-xyz) even if the uuid has changed.
 */
void oldChatroomSupport() {
	RedisServer redis{};
	const auto testDir = TmpDir(__FUNCTION__ + "."s);
	Server proxy{
	    {
	        {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	        {"module::Registrar/db-implementation", "redis"},
	        {"module::Registrar/enable-gruu", "true"},
	        {"module::Registrar/redis-server-domain", "localhost"},
	        {"module::Registrar/redis-server-port", std::to_string(redis.port())},
	        {"module::Registrar/redis-slave-check-period", "1" /* second */},
	        {"conference-server/database-backend", "sqlite"},
	        {"conference-server/database-connection-string", "/dev/null"},
	        {"conference-server/conference-factory-uris", "sip:conference-factory@sip.example.org"},
	        {"conference-server/conference-focus-uris", "sip:conference-focus@sip.example.org"},
	        {"conference-server/state-directory", testDir.path() / "conf-server"},
	    },
	};
	proxy.start();
	CoreAssert asserter{proxy};
	auto& registrar = proxy.getRegistrarDb();

	auto backend = dynamic_cast<const RegistrarDbRedisAsync*>(&registrar->getRegistrarBackend());
	BC_HARD_ASSERT(backend != nullptr);
	auto& registrarBackend = const_cast<RegistrarDbRedisAsync&>(*backend); // we want to force a behavior
	BC_ASSERT(registrarBackend.connect() != std::nullopt);

	class FakeListener : public ContactUpdateListener {
		void onRecordFound(const std::shared_ptr<Record>&) override {
			recorded = true;
		}
		void onError(const SipStatus&) override {
		}
		void onInvalid(const SipStatus&) override {
		}
		void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
			updated = true;
		}

	public:
		bool recorded{};
		bool updated{};
	};
	std::shared_ptr<FakeListener> listener = std::make_shared<FakeListener>();
	const auto bindingUrl = "sip:chatroom-xyz@sip.example.org;gr=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
	flexisip::SipUri uri(bindingUrl);

	BindingParameters parameter;
	parameter.callId = "dummy";
	parameter.globalExpire = 100;
	parameter.alias = false;
	parameter.version = 0;
	parameter.withGruu = true;

	// Simulate an old chatroom creation with a uuid 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'.
	sofiasip::Home home{};
	const auto gruuA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
	sip_contact_t* sipContactOnA = sip_contact_create(
	    home.home(), reinterpret_cast<const url_string_t*>(url_make(home.home(), "sip:127.0.0.1:6064;transport=tcp")),
	    su_strdup(home.home(), ("+sip.instance=" + UriUtils::grToUniqueId(gruuA)).c_str()), nullptr);
	registrar->bind(uri, sipContactOnA, parameter, listener);
	BC_ASSERT(asserter.iterateUpTo(10, [&listener] { return listener->recorded; }));

	TestConferenceServer conf{proxy};
	BC_ASSERT_CPP_EQUAL(listener->updated, false);

	// Bind chatroom with a new uuid, the previous contact must be updated.
	conf.bindChatRoom(bindingUrl, "sip:127.0.0.1:6065;transport=tcp", listener);
	BC_ASSERT(asserter.iterateUpTo(10, [&listener] { return listener->updated; }));
}

TestSuite _("Conference",
            {
                CLASSY_TEST(conferenceServerBindsChatroomsFromDBOnInit),
                CLASSY_TEST(conferenceServerClearsOldBindingsOnInit),
                CLASSY_TEST(inviteResentOnReconnect),
                CLASSY_TEST(oldChatroomSupport),
            });
} // namespace
