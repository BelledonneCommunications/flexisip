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

#include <flexisip/agent.hh>
#include <flexisip/registrar/extended-contact.hh>
#include <flexisip/registrar/record.hh>
#include <flexisip/registrar/registrar-db.hh>

#include "conference/conference-server.hh"
#include "tester.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace std::chrono_literals;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::tester;

static shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};
static int listenerCalled = 0;

class ConferenceBindListener : public ContactUpdateListener {
public:
	void onRecordFound(const shared_ptr<Record>& r) override {
		listenerCalled++;
		if (!r) {
			BC_FAIL("One record must be found.");
			return;
		}
		auto extendedContactList = r->getExtendedContacts();
		BC_ASSERT_EQUAL(extendedContactList.size(), 1, int, "%i");
		for (auto extendedContact : extendedContactList) {
			SipUri actualUri{extendedContact->mSipContact->m_url};
			BC_ASSERT_STRING_EQUAL(actualUri.str().c_str(), "sip:127.0.0.1:6064;transport=tcp");
		}
	}
	void onError() override {
		listenerCalled++;
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onInvalid() override {
		listenerCalled++;
		BC_FAIL("Only onRecordFound must be called.");
	}
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		listenerCalled++;
		BC_FAIL("Only onRecordFound must be called.");
	}
};

/**
 * Test to acknowledge that conference-server correctly bind the chat rooms from the chat rooms DB into the registrar DB
 * during its initialization.
 */
static void chatRoomBindingOnInitTest() {

	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(bcTesterRes("config/flexisip_conference.conf"));
	agent->loadConfig(cfg);

	// Conference Server configuration
	auto gs = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	gs->get<ConfigString>("database-backend")->set("sqlite");
	// This database already contains 2 chatrooms
	gs->get<ConfigString>("database-connection-string")->set(bcTesterRes("db/conference_tester.db"));
	gs->get<ConfigString>("outbound-proxy")->set("sip:127.0.0.1:5060;transport=tcp");
	gs->get<ConfigString>("transport")->set("sip:127.0.0.1:6064;transport=tcp");
	gs->get<ConfigString>("conference-factory-uri")->set("sip:focus@sip.example.org");

	auto conferenceServer = make_shared<ConferenceServer>(agent->getPreferredRoute(), root);
	conferenceServer->init();

	RegistrarDb::get()->fetch(SipUri{"sip:chatroom@sip.linphone.org"}, make_shared<ConferenceBindListener>(), true);
	RegistrarDb::get()->fetch(SipUri{"sip:chatroom2@sip.linphone.org"}, make_shared<ConferenceBindListener>(), true);

	agent->start("", "");

	// Timer to break infinite loop on test error
	auto beforePlus5 = system_clock::now() + 5s;
	while (listenerCalled != 2 && beforePlus5 >= system_clock::now()) {
		agent->getRoot()->step(100ms);
	}

	BC_ASSERT_EQUAL(listenerCalled, 2, int, "%i");
}

namespace {
TestSuite _("Conference",
            {
                TEST_NO_TAG("On conference server load test", chatRoomBindingOnInitTest),
            },
            Hooks()
                .beforeEach([] {
	                root = make_shared<sofiasip::SuRoot>();
	                agent = make_shared<Agent>(root);
                })
                .afterEach([] {
	                agent->unloadConfig();
	                RegistrarDb::resetDB();
	                agent.reset();
	                root.reset();
                }));
}
