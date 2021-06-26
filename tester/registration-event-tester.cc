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

#include <bctoolbox/logging.h>

#include <linphone++/linphone.hh>

#include <flexisip/agent.hh>
#include <flexisip/configmanager.hh>
#include <flexisip/registrardb.hh>

#include "conference/conference-server.hh"
#include "registration-events/client.hh"
#include "registration-events/server.hh"
#include "tester.hh"


using namespace std;
using namespace linphone;

namespace flexisip {

class BcAssert {
public:
	void addCustomIterate(const std::function<void ()> &iterate) {
		mIterateFuncs.push_back(iterate);
	}
	bool waitUntil( std::chrono::duration<double> timeout ,const std::function<bool ()> &condition) {
		auto start = std::chrono::steady_clock::now();

		bool result;
		while (!(result = condition()) && (std::chrono::steady_clock::now() - start < timeout)) {
			for (const auto &iterate:mIterateFuncs) {
				iterate();
			}
			usleep(100);
		}
		return result;
	}
	bool wait(const std::function<bool ()> &condition) {
		return waitUntil(std::chrono::seconds(10),condition);
	}

private:
	std::list<std::function<void ()>> mIterateFuncs;
};

class CoreAssert : public BcAssert {
public:
	CoreAssert(std::initializer_list<std::shared_ptr<linphone::Core>> cores) : BcAssert{} {
		for (const auto& core: cores) {
			addCustomIterate([core] {
				core->iterate();
			});
		}
	}
};

class RegEventAssert : public CoreAssert {
public :
	RegEventAssert(std::initializer_list<std::shared_ptr<linphone::Core>> cores,Agent * a) : CoreAssert(cores) {
		addCustomIterate([a] {su_root_step(a->getRoot(), 10);});
	}
};

static void basic() {
	// ================================================================
	//  Instanciate and configure all the daemon required for the test
	// ================================================================

	// Agent initialisation

	auto *root = su_root_create(nullptr);
	auto a = make_shared<Agent>(root);
	auto *agent = a->getAgent();

	auto *cfg = GenericManager::get();
	cfg->load(string{TESTER_DATA_DIR} + "/config/flexisip_regevent.conf");
	agent->loadConfig(cfg);


	// Client initialisation

	auto clientCore = Factory::get()->createCore("","", nullptr);
	clientCore->getConfig()->setString("storage", "backend", "sqlite3");
	clientCore->getConfig()->setString("storage", "uri", ":memory:");

	auto clientTransport = Factory::get()->createTransports();
	clientTransport->setTcpPort(rand() %0x0FFF + 1014);
	clientCore->setTransports(clientTransport);
	clientCore->start();

	auto me = Factory::get()->createAddress("sip:test@sip.example.org");

	auto proxy = clientCore->createProxyConfig();
	proxy->setIdentityAddress(me);
	proxy->enableRegister(true);
	proxy->setConferenceFactoryUri("sip:focus@sip.example.org");
	proxy->setServerAddr("sip:127.0.0.1:5060;transport=tcp");
	proxy->setRoute("sip:127.0.0.1:5060;transport=tcp");
	clientCore->addProxyConfig(proxy);
	clientCore->setDefaultProxyConfig(proxy);


	// RegEvent Server

	auto regEventCore = Factory::get()->createCore("", "", nullptr);
	regEventCore->getConfig()->setString("storage", "backend", "sqlite3");
	regEventCore->getConfig()->setString("storage", "uri", ":memory:");

	auto regEventTransport = Factory::get()->createTransports();
	auto regEventPort = rand() % 0x0FFF + 1014;
	regEventTransport->setTcpPort(regEventPort);
	regEventCore->setTransports(regEventTransport);
	regEventCore->addListener(make_shared<flexisip::RegistrationEvent::Server>(root));
	regEventCore->start();


	// Conference Server

	auto confServerCfg = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	confServerCfg->get<ConfigString>("database-backend")->set("sqlite");
	confServerCfg->get<ConfigString>("database-connection-string")->set(":memory:");
	confServerCfg->get<ConfigString>("outbound-proxy")->set("sip:127.0.0.1:5060;transport=tcp");
	confServerCfg->get<ConfigString>("transport")->set("sip:127.0.0.1:6064;transport=tcp");
	confServerCfg->get<ConfigString>("conference-factory-uri")->set("sip:focus@sip.example.org");


	// Registrars / Local confs
	confServerCfg->get<ConfigStringList>("local-domains")->set("sip.example.org 127.0.0.1 [2a01:e0a:1ce:c860:f03d:d06:649f:6cfc]");

	auto conferenceServer = make_shared<ConferenceServer>(a->getPreferredRoute(), root);
	conferenceServer->init();


	// Proxy configuration

	auto *global = GenericManager::get()->getRoot()->get<GenericStruct>("global");
	global->get<ConfigStringList>("transports")->set("sip:127.0.0.1:5060");


	// Configure module regevent

	auto *registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("sip.example.org");

	auto *regEventConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::RegEvent");
	regEventConf->get<ConfigString>("regevent-server")->set("sip:127.0.0.1:" + to_string(regEventPort) + ";transport=tcp");

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

	sofiasip::Home home{};

	const SipUri participantFromUri{"sip:participant1@test.com"};
	const SipUri otherParticipantFromUri{"sip:participant2@test.com"};
	const SipUri participantRebindFromUri{"sip:participant_re_bind@test.com"};


	// Fill the Regisrar DB with participants

	BindingParameters parameter{};
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_1";
	parameter.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameter.withGruu = true;

	auto participantContact = sip_contact_create(
		home.home(),
		reinterpret_cast<const url_string_t *>(participantFromUri.str().c_str()),
		"+sip.instance=\"<f75b0df3-1836-4b83-b7f6-00e48842c9a7-ubuntu>\"",
		"+org.linphone.specs=\"groupchat,lime\"",
		nullptr
	);

	RegistrarDb::get()->bind(
		participantFromUri,
		participantContact,
		parameter,
		make_shared<BindListener>()
	);

	const string firstDeviceName{"RedHat"};

	BindingParameters parameter2{};
	parameter2.globalExpire = 1000;
	parameter2.callId = "random_id_necessary_to_bind_2";
	parameter2.userAgent = "Linphone2 (" + firstDeviceName + ") LinphoneCore";
	parameter2.withGruu = true;

	RegistrarDb::get()->bind(
		otherParticipantFromUri,
		sip_contact_create(
			home.home(),
			reinterpret_cast<const url_string_t *>(otherParticipantFromUri.str().c_str()),
			"+sip.instance=\"<ab959409-7076-464e-85f8-7f8a84864618-redhat>\"",
			"+org.linphone.specs=\"groupchat,lime\"",
			nullptr
		),
		parameter2,
		make_shared<BindListener>()
	);

	const string lastDeviceName{"Debian"};

	BindingParameters parameter3{};
	parameter3.globalExpire = 1000;
	parameter3.callId = "random_id_necessary_to_bind_3";
	parameter3.userAgent = "Linphone2 (" + lastDeviceName + ") LinphoneCore";
	parameter3.withGruu = true;

	RegistrarDb::get()->bind(
		otherParticipantFromUri,
		sip_contact_create(
			home.home(),
			reinterpret_cast<const url_string_t *>(otherParticipantFromUri.str().c_str()),
			"+sip.instance=\"<6d6ed907-dbd0-4dfc-abf8-6470310bc4ed-debian>\"",
			nullptr
		),
		parameter3,
		make_shared<BindListener>()
	);


	// ================
	//  Start the test
	// ================

	list<shared_ptr<Address>> participants{
		Factory::get()->createAddress(participantFromUri.str()),
		Factory::get()->createAddress(otherParticipantFromUri.str())
	};

	auto chatRoomParams = clientCore->createDefaultChatRoomParams();
	chatRoomParams->enableGroup(true);
	auto chatRoom = clientCore->createChatRoom(chatRoomParams, proxy->getContact(), "Chatroom with remote", participants);

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (const auto& participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}
		return numberOfDevices == 2;
	}));

	auto participantsTest = chatRoom->getParticipants();
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == participantFromUri.str());
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFromUri.str());
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == firstDeviceName);


	// Let's add a new device

	const string newDeviceName{"New Device"};

	BindingParameters parameter4{};
	parameter4.globalExpire = 1000;
	parameter4.callId = "random_id_necessary_to_bind_4";
	parameter4.userAgent = "Linphone2 (" + newDeviceName + ") LinphoneCore";
	parameter4.withGruu = true;

	auto otherParticipantContact = sip_contact_create(
		home.home(),
		reinterpret_cast<const url_string_t *>(otherParticipantFromUri.str().c_str()),
		"+sip.instance=\"<9db326ca-1ee5-400b-b7f1-d31086530a35-new-device>\"",
		"+org.linphone.specs=\"groupchat,lime\"",
		nullptr
	);

	RegistrarDb::get()->bind(
		otherParticipantFromUri,
		otherParticipantContact,
		parameter4,
		make_shared<BindListener>()
	);
	RegistrarDb::get()->publish(otherParticipantFromUri.str().substr(4), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (const auto& participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 3;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFromUri.str());
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().front()->getName() == firstDeviceName);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == newDeviceName);


	// Remove a device

	parameter4.globalExpire = 0;
	parameter4.callId = "random_id_necessary_to_bind_5";

	RegistrarDb::get()->bind(
		otherParticipantFromUri,
		otherParticipantContact,
		parameter4,
		make_shared<BindListener>()
	);
	RegistrarDb::get()->publish(otherParticipantFromUri.str().substr(4), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (const auto& participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.size() == 2);
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == participantFromUri.str());
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFromUri.str());
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().size() == 1);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == firstDeviceName);


	// Remove the first participant

	parameter.globalExpire = 0;
	parameter.callId = "random_id_necessary_to_bind_6";

	RegistrarDb::get()->bind(
		participantFromUri,
		participantContact,
		parameter,
		make_shared<BindListener>()
	);
	RegistrarDb::get()->publish(participantFromUri.str().substr(4), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (const auto& participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 1;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.size() == 1);
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == otherParticipantFromUri.str());


	// Reroute everything locally on the Conference Server

	confServerCfg->get<ConfigStringList>("local-domains")->set("");


	// Re-add the first participant, with the routing disabled

	BindingParameters parameterReBind{};
	parameterReBind.callId = "random_id_necessary_to_rebind_1";
	parameterReBind.globalExpire = 1000;
	parameterReBind.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameterReBind.withGruu = true;

	auto participantReBindContact = sip_contact_create(
		home.home(),
		reinterpret_cast<const url_string_t *>(participantRebindFromUri.str().c_str()),
		"+sip.instance=\"<f75b0df3-1836-4b83-b7f6-00e48842c9a7-re-ubuntu>\"",
		"+org.linphone.specs=\"groupchat,lime\"",
		nullptr
	);

	RegistrarDb::get()->bind(
		participantRebindFromUri,
		participantReBindContact,
		parameterReBind,
		make_shared<BindListener>()
	);

	auto reBindParticipant = linphone::Factory::get()->createAddress(participantRebindFromUri.str());
	chatRoom->addParticipant(reBindParticipant);

	BC_ASSERT_TRUE(RegEventAssert({clientCore,regEventCore},agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (const auto& participant: chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));


	// Check if the participant was still added (locally)

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.size() == 2);
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == otherParticipantFromUri.str());
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == participantRebindFromUri.str());
}

static test_t tests[] = {
	TEST_NO_TAG("Basic sub", basic),
};

test_suite_t registration_event_suite = {
	"Registration Event",
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	sizeof(tests) / sizeof(tests[0]),
	tests
};

} // namespace flexisip
