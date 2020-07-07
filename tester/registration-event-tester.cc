/*
 * Copyright (C) 2020 Belledonne Communications SARL
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include "tester.hh"
#include <flexisip/agent.hh>
#include <linphone++/linphone.hh>
#include "bctoolbox/logging.h"
#include <flexisip/configmanager.hh>
#include <flexisip/registrardb.hh>

#include "conference/registration-events/client.hh"
#include "conference/registration-events/server.hh"
#include "conference/conference-server.hh"

using namespace std;
using namespace linphone;
using namespace flexisip;

static void basic() {
	// Agent initialisation

	su_root_t *root = su_root_create(NULL);
	shared_ptr<Agent> a = make_shared<Agent>(root);
	Agent *agent = a->getAgent();

	GenericManager *cfg = GenericManager::get();
	cfg->load("/flexisip.conf");
	agent->loadConfig(cfg);

	// Client initialisation

	shared_ptr<Core> clientCore = Factory::get()->createCore("","", nullptr);
	clientCore->getConfig()->setString("storage", "backend", "sqlite3");
	clientCore->getConfig()->setString("storage", "uri", ":memory:");

	shared_ptr<Transports> clientTransport = Factory::get()->createTransports();
	clientTransport->setTcpPort(rand() %0x0FFF + 1014);
	clientCore->setTransports(clientTransport);
	clientCore->start();

	auto me = Factory::get()->createAddress("sip:test@sip.example.org");

	shared_ptr<ProxyConfig> proxy = clientCore->createProxyConfig();
	proxy->setIdentityAddress(me);
	proxy->enableRegister(true);
	proxy->setConferenceFactoryUri("sip:focus@sip.example.org");
	proxy->setServerAddr("sip:127.0.0.1:5060;transport=tcp");
	proxy->setRoute("sip:127.0.0.1:5060;transport=tcp");
	clientCore->addProxyConfig(proxy);
	clientCore->setDefaultProxyConfig(proxy);

	// RegEvent Server

	shared_ptr<Core> regEventCore = Factory::get()->createCore("", "", nullptr);
	regEventCore->getConfig()->setString("storage", "backend", "sqlite3");
	regEventCore->getConfig()->setString("storage", "uri", ":memory:");

	shared_ptr<Transports> regEventTransport = Factory::get()->createTransports();
	int regEventPort = rand() %0x0FFF + 1014;
	regEventTransport->setTcpPort(regEventPort);
	regEventCore->setTransports(regEventTransport);
	regEventCore->addListener(make_shared<RegistrationEvent::Server>());
	regEventCore->start();

	// Conference Server

	GenericStruct *gs = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	gs->get<ConfigString>("database-backend")->set("sqlite");
	gs->get<ConfigString>("database-connection-string")->set(":memory:");
	gs->get<ConfigString>("outbound-proxy")->set("sip:127.0.0.1:5060;transport=tcp");
	gs->get<ConfigString>("transport")->set("sip:127.0.0.1:6064;transport=tcp");
	gs->get<ConfigString>("conference-factory-uri")->set("sip:focus@sip.example.org");

	// Registrars / Local confs
	gs->get<ConfigString>("local-domains")->set("sip.example.org 127.0.0.1 [2a01:e0a:1ce:c860:f03d:d06:649f:6cfc]");

	auto conferenceServer = make_shared<ConferenceServer>(a->getPreferredRoute(), root);
	conferenceServer->init();

	// Proxy configuration

	GenericStruct *global = GenericManager::get()->getRoot()->get<GenericStruct>("global");
	global->get<ConfigStringList>("transports")->set("sip:127.0.0.1:5060;transport=tcp");

	// Configure module regevent

	GenericStruct *registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("sip.example.org");

	GenericStruct *regEventConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::RegEvent");
	regEventConf->get<ConfigString>("regevent-server")->set(string("sip:127.0.0.1:").append(to_string(regEventPort)).append(";transport=tcp"));

	agent->start("", "");

	while (proxy->getState() != RegistrationState::Ok) {
		clientCore->iterate();
		su_root_step(a->getRoot(), 100);
	}

	// Fill the RegistrarDB

	class BindListener : public ContactUpdateListener {
	public:
		void onRecordFound(const shared_ptr<Record> &r) override {}
		void onError() override {}
		void onInvalid() override {}
		void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) override {}
	};

	string participantFrom = "sip:participant1@test.com";
	string otherParticipantFrom = "sip:participant2@test.com";

	// Fill the Regisrar DB with participants

	SofiaAutoHome home;

	BindingParameters parameter;
	parameter.globalExpire = 1000;
	parameter.callId = "123456789";
	parameter.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameter.withGruu = true;

	RegistrarDb::get()->bind(
		url_make(home.home(), participantFrom.c_str()),
		sip_contact_create(
			home.home(),
			(url_string_t *)participantFrom.c_str(),
			string("+sip.instance=\"<1234>\"").c_str(),
			string("+org.linphone.specs=\"groupchat,lime\"").c_str(),
			nullptr
		),
		parameter,
		make_shared<BindListener>()
	);

	BindingParameters parameter2;
	parameter2.globalExpire = 1000;
	parameter2.callId = "1234567890";
	parameter2.userAgent = "Linphone2 (RedHat) LinphoneCore";
	parameter2.withGruu = true;

	RegistrarDb::get()->bind(
		url_make(home.home(), otherParticipantFrom.c_str()),
		sip_contact_create(
			home.home(),
			(url_string_t *)otherParticipantFrom.c_str(),
			string("+sip.instance=\"<4567>\"").c_str(),
			string("+org.linphone.specs=\"groupchat,lime\"").c_str(),
			nullptr
		),
		parameter2,
		make_shared<BindListener>()
	);

	BindingParameters parameter3;
	parameter3.globalExpire = 1000;
	parameter3.callId = "1234567890";
	parameter3.userAgent = "Linphone2 (Debian) LinphoneCore";
	parameter3.withGruu = true;

	RegistrarDb::get()->bind(
		url_make(home.home(), otherParticipantFrom.c_str()),
		sip_contact_create(
			home.home(),
			(url_string_t *)otherParticipantFrom.c_str(),
			string("+sip.instance=\"<8900>\"").c_str(),
			nullptr
		),
		parameter3,
		make_shared<BindListener>()
	);

	list<shared_ptr<Address>> participants;
	participants.push_back(Factory::get()->createAddress(participantFrom));
	participants.push_back(Factory::get()->createAddress(otherParticipantFrom));

	auto chatRoomParams = clientCore->createDefaultChatRoomParams();
	chatRoomParams->enableGroup(true);
	auto chatRoom = clientCore->createChatRoom(chatRoomParams, proxy->getContact(), "Chatroom with remote", participants);

	class BcAssert {
	public:
		void addCustomIterate(const std::function<void ()> &iterate) {
			mIterateFuncs.push_back(iterate);
		}
		bool waitUntil( std::chrono::duration<double> timeout ,const std::function<bool ()> &condition) {
			auto start = std::chrono::steady_clock::now();

			bool_t result;
			while (!(result = condition()) && (std::chrono::steady_clock::now() - start < timeout)) {
				for (const std::function<void ()> iterate:mIterateFuncs) {
					iterate();
				}
				usleep(100);
			}
			return result;
		}
		bool wait(const std::function<bool ()> &condition) {
			return waitUntil(std::chrono::seconds(2),condition);
		}
	private:
		list<std::function<void ()>> mIterateFuncs;
	};

	class CoreAssert : public BcAssert {
	public:
		CoreAssert(std::initializer_list<shared_ptr<linphone::Core>> cores) {
			for (shared_ptr<linphone::Core> core: cores) {
				addCustomIterate([core] {
					core->iterate();
				});
			}
		}
	};

	class RegEventAssert : public CoreAssert {
	public :
		RegEventAssert(std::initializer_list<shared_ptr<linphone::Core>> cores,Agent * a) : CoreAssert(cores) {
			addCustomIterate([a] {su_root_step(a->getRoot(), 10);});
		}
	};

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));

	auto participantsTest = chatRoom->getParticipants();
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == participantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFrom);

	// Let's add a new device

	string newDeviceName = "Slack";

	BindingParameters parameter4;
	parameter4.globalExpire = 1000;
	parameter4.callId = "1234567890";
	parameter4.userAgent = string("Linphone2 (").append(newDeviceName).append(") LinphoneCore");
	parameter4.withGruu = true;

	RegistrarDb::get()->bind(
		url_make(home.home(), otherParticipantFrom.c_str()),
		sip_contact_create(
			home.home(),
			(url_string_t *)otherParticipantFrom.c_str(),
			string("+sip.instance=\"<1001>\"").c_str(),
			string("+org.linphone.specs=\"groupchat,lime\"").c_str(),
			nullptr
		),
		parameter4,
		make_shared<BindListener>()
	);
	RegistrarDb::get()->publish(otherParticipantFrom.substr(4).c_str(), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 3;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == newDeviceName);

	// And we remove one of the devices
	RegistrarDb::get()->clear(url_make(home.home(), otherParticipantFrom.c_str()), make_shared<BindListener>());

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));
}

static test_t tests[] = {
	TEST_NO_TAG("Basic sub", basic),
};

test_suite_t registration_event_suite = {
	"Registration Event",
	NULL,
	NULL,
	NULL,
	NULL,
	sizeof(tests) / sizeof(tests[0]),
	tests
};
