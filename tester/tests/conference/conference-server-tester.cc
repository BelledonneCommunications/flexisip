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

#include <chrono>
#include <initializer_list>
#include <memory>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "linphone++/enums.hh"

#include "flexisip/registrar/registar-listeners.hh"

#include "agent.hh"
#include "conference/chatroom-prefix.hh"
#include "conference/conference-server.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"
#include "registrardb-internal.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/chat-room-builder.hh"
#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/core-assert.hh"
#include "utils/mysql-server.hh"
#include "utils/proxy-server.hh"
#include "utils/string-utils.hh"
#include "utils/test-conference-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

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
			SLOGD << "BEDUG " << __PRETTY_FUNCTION__ << " chatroom: " << chatroom->cPtr();
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
	Server proxy{{
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0;transport=tcp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::Registrar/reg-domains", "sip.example.org"},

	    // `sqlite` breaks on CentOS7 with inexplicable disk I/O errors
	    {"conference-server/database-backend", "mysql"},
	    {"conference-server/database-connection-string", mysqlServer.connectionString()},
	    {"conference-server/conference-factory-uris", confFactoryUri},
	}};
	proxy.start();
	GenericManager::get()
	    ->getRoot()
	    ->get<GenericStruct>("conference-server")
	    ->get<ConfigValue>("outbound-proxy")
	    ->set("sip:127.0.0.1:"s + proxy.getFirstPort() + ";transport=tcp");
	auto* registrar = dynamic_cast<RegistrarDbInternal*>(RegistrarDb::get());
	BC_HARD_ASSERT_TRUE(registrar != nullptr);
	const auto& records = registrar->getAllRecords();
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 0);
	auto clientBuilder = proxy.clientBuilder();
	clientBuilder.setConferenceFactoryUri(confFactoryUri).setLimeX3DH(OnOff::Off);
	const auto me = clientBuilder.build("I@sip.example.org");
	const auto you = clientBuilder.build("you@sip.example.org");
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 2);
	CoreAssert asserter{proxy, you, me};
	auto chatroomBuilder = me.chatroomBuilder();
	chatroomBuilder.setBackend(linphone::ChatRoomBackend::FlexisipChat).setGroup(OnOff::On);
	const auto listener = make_shared<AllJoinedWaiter>();
	const auto conferenceServerUri = [confServerCfg =
	                                      GenericManager::get()->getRoot()->get<GenericStruct>("conference-server")] {
		return confServerCfg->get<ConfigString>("transport")->read();
	};
	{ // Populate conference server's DB
		mysqlServer.waitReady();
		const TestConferenceServer conferenceServer{*proxy.getAgent()};
		BC_HARD_ASSERT_CPP_EQUAL(records.size(), 2 /* users */ + 1 /* factory */);
		const auto& inMyRoom = you.getMe();
		listener->setChatrooms({
		    chatroomBuilder.setSubject("Boom").build({inMyRoom}),
		    chatroomBuilder.setSubject("Boom").build({inMyRoom}),
		    chatroomBuilder.setSubject("Boom").build({inMyRoom}),
		    chatroomBuilder.setSubject("Boom").build({inMyRoom}),
		});

		asserter
		    .iterateUpTo(8,
		                 [&chatrooms = listener->getChatrooms()] {
			                 FAIL_IF(0 < chatrooms.size());
			                 return ASSERTION_PASSED();
		                 })
		    .assert_passed();

		BC_ASSERT_CPP_EQUAL(listener->getChatrooms().size(), 0);
		BC_ASSERT_CPP_EQUAL(records.size(), 2 /* users */ + 1 /* factory */ + 4 /* chatrooms */);
		for (const auto& record : records) {
			if (!StringUtils::startsWith(record.first, conference::CHATROOM_PREFIX)) continue;

			const auto& contacts = record.second->getExtendedContacts();
			BC_ASSERT_CPP_EQUAL(contacts.size(), 1);
			BC_ASSERT_CPP_EQUAL(contacts.latest()->get()->urlAsString(), conferenceServerUri());
		}

	} // Shutdown conference server
	registrar->clearAll();

	// Spin it up again
	const TestConferenceServer conferenceServer{*proxy.getAgent()};

	// The conference server restored its chatrooms from DB and bound them back on the Registrar
	BC_ASSERT_CPP_EQUAL(records.size(), 1 /* factory */ + 4 /* chatrooms */);
	for (const auto& record : records) {
		const auto& contacts = record.second->getExtendedContacts();
		BC_ASSERT_CPP_EQUAL(contacts.size(), 1);
		BC_ASSERT_CPP_EQUAL(contacts.latest()->get()->urlAsString(), conferenceServerUri());
	}
}

TestSuite _("Conference",
            {CLASSY_TEST(conferenceServerBindsChatroomsFromDBOnInit)},
            Hooks()
                .beforeSuite([] {
	                RegistrarDb::resetDB();
	                return 0;
                })
                .afterSuite([] {
	                RegistrarDb::resetDB();
	                return 0;
                }));
} // namespace
