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

#include <bctoolbox/logging.h>

#include <linphone++/linphone.hh>

#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/sofia-wrapper/su-root.hh"

#include "agent.hh"
#include "conference/conference-server.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/registrar-db.hh"
#include "registration-events/client.hh"
#include "registration-events/server.hh"
#include "tester.hh"
#include "utils/asserts.hh"
#include "utils/core-assert.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace linphone;

namespace flexisip {
namespace tester {

static void basic() {
	// Agent initialisation

	auto root = make_shared<sofiasip::SuRoot>();
	shared_ptr<Agent> a = make_shared<Agent>(root);
	Agent* agent = a->getAgent();

	GenericManager* cfg = GenericManager::get();
	cfg->load(bcTesterRes("config/flexisip_regevent.conf"));
	agent->loadConfig(cfg);

	// Client initialisation

	shared_ptr<Core> clientCore = Factory::get()->createCore("", "", nullptr);
	clientCore->getConfig()->setString("storage", "backend", "sqlite3");
	clientCore->getConfig()->setString("storage", "uri", ":memory:");

	shared_ptr<Transports> clientTransport = Factory::get()->createTransports();
	clientTransport->setTcpPort(rand() % 0x0FFF + 1014);
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
	int regEventPort = rand() % 0x0FFF + 1014;
	regEventTransport->setTcpPort(regEventPort);
	regEventCore->setTransports(regEventTransport);
	regEventCore->addListener(make_shared<flexisip::RegistrationEvent::Server>(root));
	regEventCore->start();

	// Conference Server

	GenericStruct* gs = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	gs->get<ConfigString>("database-backend")->set("sqlite");
	gs->get<ConfigString>("database-connection-string")->set(":memory:");
	gs->get<ConfigString>("outbound-proxy")->set("sip:127.0.0.1:5060;transport=tcp");
	gs->get<ConfigString>("transport")->set("sip:127.0.0.1:6064;transport=tcp");
	gs->get<ConfigString>("conference-factory-uri")->set("sip:focus@sip.example.org");

	// Registrars / Local confs
	gs->get<ConfigStringList>("local-domains")->set("sip.example.org 127.0.0.1 [2a01:e0a:1ce:c860:f03d:d06:649f:6cfc]");

	auto conferenceServer = make_shared<ConferenceServer>(a->getPreferredRoute(), root);
	conferenceServer->init();

	// Proxy configuration

	GenericStruct* global = GenericManager::get()->getRoot()->get<GenericStruct>("global");
	global->get<ConfigStringList>("transports")->set("sip:127.0.0.1:5060;transport=tcp");

	// Configure module regevent

	GenericStruct* registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("sip.example.org");

	GenericStruct* regEventConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::RegEvent");
	regEventConf->get<ConfigString>("regevent-server")
	    ->set(string("sip:127.0.0.1:").append(to_string(regEventPort)).append(";transport=tcp"));

	agent->start("", "");

	while (proxy->getState() != RegistrationState::Ok) {
		clientCore->iterate();
		a->getRoot()->step(100ms);
	}

	// Fill the RegistrarDB

	class BindListener : public ContactUpdateListener {
	public:
		void onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) override {
		}
		void onError() override {
		}
		void onInvalid() override {
		}
		void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
		}
	};

	sofiasip::Home home;

	string participantFrom = "sip:participant1@test.com";
	SipUri participantUrl{participantFrom};
	string otherParticipantFrom = "sip:participant2@test.com";
	SipUri otherParticipantUrl{otherParticipantFrom};
	string participantRebindFrom = "sip:participant_re_bind@test.com";
	SipUri participantRebindUrl{participantRebindFrom};

	// Fill the Regisrar DB with participants

	BindingParameters parameter;
	parameter.globalExpire = 1000;
	parameter.callId = "random_id_necessary_to_bind_1";
	parameter.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameter.withGruu = true;

	auto participantContact =
	    sip_contact_create(home.home(), (url_string_t*)participantFrom.c_str(),
	                       string("+sip.instance=\"<f75b0df3-1836-4b83-b7f6-00e48842c9a7-ubuntu>\"").c_str(),
	                       string("+org.linphone.specs=\"groupchat,lime\"").c_str(), nullptr);

	RegistrarDb::get()->bind(participantUrl, participantContact, parameter, make_shared<BindListener>());

	string firstDeviceName = "RedHat";

	BindingParameters parameter2;
	parameter2.globalExpire = 1000;
	parameter2.callId = "random_id_necessary_to_bind_2";
	parameter2.userAgent = string("Linphone2 (").append(firstDeviceName).append(") LinphoneCore");
	parameter2.withGruu = true;

	RegistrarDb::get()->bind(
	    otherParticipantUrl,
	    sip_contact_create(home.home(), (url_string_t*)otherParticipantFrom.c_str(),
	                       string("+sip.instance=\"<ab959409-7076-464e-85f8-7f8a84864618-redhat>\"").c_str(),
	                       string("+org.linphone.specs=\"groupchat,lime\"").c_str(), nullptr),
	    parameter2, make_shared<BindListener>());

	string lastDeviceName = "Debian";

	BindingParameters parameter3;
	parameter3.globalExpire = 1000;
	parameter3.callId = "random_id_necessary_to_bind_3";
	parameter3.userAgent = string("Linphone2 (").append(lastDeviceName).append(") LinphoneCore");
	parameter3.withGruu = true;

	RegistrarDb::get()->bind(
	    otherParticipantUrl,
	    sip_contact_create(home.home(), (url_string_t*)otherParticipantFrom.c_str(),
	                       string("+sip.instance=\"<6d6ed907-dbd0-4dfc-abf8-6470310bc4ed-debian>\"").c_str(), nullptr),
	    parameter3, make_shared<BindListener>());

	list<shared_ptr<Address>> participants;
	participants.push_back(Factory::get()->createAddress(participantFrom));
	participants.push_back(Factory::get()->createAddress(otherParticipantFrom));

	auto chatRoomParams = clientCore->createDefaultChatRoomParams();
	chatRoomParams->enableGroup(true);
	auto chatRoom =
	    clientCore->createChatRoom(chatRoomParams, proxy->getContact(), "Chatroom with remote", participants);

	class RegEventAssert : public CoreAssert {
	public:
		RegEventAssert(std::initializer_list<shared_ptr<linphone::Core>> cores, Agent* a) : CoreAssert(cores) {
			addCustomIterate([a] { a->getRoot()->step(10ms); });
		}
	};

	BC_ASSERT_TRUE(RegEventAssert({clientCore, regEventCore}, agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant : chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));

	auto participantsTest = chatRoom->getParticipants();
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == participantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == firstDeviceName);

	// Let's add a new device

	string newDeviceName = "New Device";

	BindingParameters parameter4;
	parameter4.globalExpire = 1000;
	parameter4.callId = "random_id_necessary_to_bind_4";
	parameter4.userAgent = string("Linphone2 (").append(newDeviceName).append(") LinphoneCore");
	parameter4.withGruu = true;

	auto otherParticipantContact =
	    sip_contact_create(home.home(), (url_string_t*)otherParticipantFrom.c_str(),
	                       string("+sip.instance=\"<9db326ca-1ee5-400b-b7f1-d31086530a35-new-device>\"").c_str(),
	                       string("+org.linphone.specs=\"groupchat,lime\"").c_str(), nullptr);

	RegistrarDb::get()->bind(otherParticipantUrl, otherParticipantContact, parameter4, make_shared<BindListener>());
	RegistrarDb::get()->publish(otherParticipantFrom.substr(4).c_str(), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore, regEventCore}, agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant : chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 3;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().front()->getName() == firstDeviceName);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == newDeviceName);

	// Remove a device

	parameter4.globalExpire = 0;
	parameter4.callId = "random_id_necessary_to_bind_5";

	RegistrarDb::get()->bind(otherParticipantUrl, otherParticipantContact, parameter4, make_shared<BindListener>());
	RegistrarDb::get()->publish(otherParticipantFrom.substr(4).c_str(), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore, regEventCore}, agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant : chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.size() == 2);
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == participantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == otherParticipantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().size() == 1);
	BC_ASSERT_TRUE(participantsTest.back()->getDevices().back()->getName() == firstDeviceName);

	// Remove the first participant

	parameter.globalExpire = 0;
	parameter.callId = "random_id_necessary_to_bind_6";

	RegistrarDb::get()->bind(participantUrl, participantContact, parameter, make_shared<BindListener>());
	RegistrarDb::get()->publish(participantFrom.substr(4).c_str(), "");

	BC_ASSERT_TRUE(RegEventAssert({clientCore, regEventCore}, agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant : chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 1;
	}));

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.size() == 1);
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == otherParticipantFrom);

	// Reroute everything locally on the Conference Server

	gs->get<ConfigStringList>("local-domains")->set("");

	// Re-add the first participant, with the routing disabled

	BindingParameters parameterReBind;
	parameterReBind.callId = "random_id_necessary_to_rebind_1";
	parameterReBind.globalExpire = 1000;
	parameterReBind.userAgent = "Linphone1 (Ubuntu) LinphoneCore";
	parameterReBind.withGruu = true;

	auto participantReBindContact =
	    sip_contact_create(home.home(), (url_string_t*)participantRebindFrom.c_str(),
	                       string("+sip.instance=\"<f75b0df3-1836-4b83-b7f6-00e48842c9a7-re-ubuntu>\"").c_str(),
	                       string("+org.linphone.specs=\"groupchat,lime\"").c_str(), nullptr);

	RegistrarDb::get()->bind(participantRebindUrl, participantReBindContact, parameterReBind,
	                         make_shared<BindListener>());

	shared_ptr<linphone::Address> reBindParticipant =
	    linphone::Factory::get()->createAddress(participantRebindFrom.c_str());
	chatRoom->addParticipant(reBindParticipant);

	BC_ASSERT_TRUE(RegEventAssert({clientCore, regEventCore}, agent).wait([chatRoom] {
		int numberOfDevices = 0;
		for (auto participant : chatRoom->getParticipants()) {
			numberOfDevices += participant->getDevices().size();
		}

		return numberOfDevices == 2;
	}));

	// Check if the participant was still added (locally)

	participantsTest = chatRoom->getParticipants();

	BC_ASSERT_TRUE(participantsTest.size() == 2);
	BC_ASSERT_TRUE(participantsTest.front()->getAddress()->asString() == otherParticipantFrom);
	BC_ASSERT_TRUE(participantsTest.back()->getAddress()->asString() == participantRebindFrom);
}

namespace {
TestSuite::Disabled // Remove the "Disabled" suffix when the 'Registration Event' suite is fixed.
    _("Registration Event",
      {
          TEST_NO_TAG("Basic sub", basic),
      });
}
} // namespace tester
} // namespace flexisip
