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
	//int proxyPort = 5060;

	// Client initialisation

	shared_ptr<Core> clientCore = Factory::get()->createCore("","", nullptr);
	clientCore->getConfig()->setString("storage", "uri", "null");
	shared_ptr<Transports> transport = Factory::get()->createTransports();
	transport->setTcpPort(rand() %0x0FFF + 1014);
	clientCore->setTransports(transport);

	auto me = Factory::get()->createAddress("sip:test@sip.example.org"/*clientCore->getIdentity()*/);
	//me->setUriParam("gr", "abcd");
	me->setPort(5060);

	// TODO REGISTER + wait
	// Flag enabled pour module registrar

	shared_ptr<ProxyConfig> proxy = clientCore->createProxyConfig();
	proxy->setIdentityAddress(me);
	proxy->enableRegister(true);
	proxy->setConferenceFactoryUri("sip:focus@sip.example.org");
	proxy->setServerAddr("sip:127.0.0.1:5060;transport=tcp");
	proxy->setRoute("sip:127.0.0.1:5060;transport=tcp");
	clientCore->addProxyConfig(proxy);
	clientCore->setDefaultProxyConfig(proxy);
	//clientCore->setPrimaryContact("sip:foobar@sip.example.org:48888;transport=tcp;gr=1234");

	// RegEvent Server

	shared_ptr<Core> regEventCore = Factory::get()->createCore("", "", nullptr);
	regEventCore->getConfig()->setString("storage", "backend", "sqlite3");
	regEventCore->getConfig()->setString("storage", "uri", ":memory:");

	shared_ptr<Transports> regEventTransport = Factory::get()->createTransports();
	int regEventPort = rand() %0x0FFF + 1014;
	regEventTransport->setTcpPort(regEventPort);
	regEventCore->setTransports(regEventTransport);

	// Agent initialisation

	su_root_t *root = su_root_create(NULL);
	shared_ptr<Agent> a = make_shared<Agent>(root);
	Agent *agent = a->getAgent();

	GenericManager *cfg = GenericManager::get();
	cfg->load("/flexisip.conf");
	agent->loadConfig(cfg);
	agent->start("", "");

	// Conference Server

	GenericStruct *gs = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	gs->get<ConfigString>("database-backend")->set("sqlite");
	gs->get<ConfigString>("database-connection-string")->set(":memory:");
	gs->get<ConfigString>("outbound-proxy")->set("sip:127.0.0.1:5060;transport=tcp");
	gs->get<ConfigString>("transport")->set("sip:127.0.0.1:6064;transport=tcp");
	gs->get<ConfigString>("conference-factory-uri")->set("sip:focus@sip.example.org");
	// Registrars / Local confs
	gs->get<ConfigString>("local-domains")->set("127.0.0.1 [2a01:e0a:1ce:c860:f03d:d06:649f:6cfc]");

	auto conferenceServer = make_shared<ConferenceServer>(a->getPreferredRoute(), root);
	conferenceServer->init();

	// Proxy configuration

	GenericStruct *global = GenericManager::get()->getRoot()->get<GenericStruct>("global");
	global->get<ConfigStringList>("transports")->set("sip:127.0.0.1:5060;transport=tcp");
	//global->get<ConfigString>("enabled")->set("true");

	// Configure module regevent

	GenericStruct *registrarConf = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	registrarConf->get<ConfigStringList>("reg-domains")->set("sip.example.org");


	while (proxy->getState() != RegistrationState::Cleared) {
		clientCore->iterate();
		//regEventCore->iterate();
		//su_root_step(a->getRoot(), 100);
	}

	// Fill the RegistrarDB

	class BindListener : public ContactUpdateListener {
	public:
		void onRecordFound(const shared_ptr<Record> &r) override {}
		void onError() override {}
		void onInvalid() override {}
		void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) override {}
	};

	string participantFrom = "sip:participant2@test.com";
	string otherParticipantFrom = "sip:participant@test.com";

	// Fill the Regisrar DB with participants

	SofiaAutoHome home;

	BindingParameters parameter;
	parameter.globalExpire = 1000;
	parameter.callId = "123456789";
	parameter.userAgent = "Linphone2 (Debian) LinphoneCore";

	RegistrarDb::get()->bind(
		url_make(home.home(), participantFrom.c_str()),
		sip_contact_create(
			home.home(),
			(url_string_t *)participantFrom.append(";gr=abcde").c_str(),
			nullptr
		),
		parameter,
		make_shared<BindListener>()
	);

	BindingParameters parameter2;
	parameter2.globalExpire = 1000;
	parameter2.callId = "1234567890";
	parameter2.userAgent = "Linphone3 (Debian) LinphoneCore";

	RegistrarDb::get()->bind(
		url_make(home.home(), participantFrom.c_str()),
		sip_contact_create(
			home.home(),
			(url_string_t *)participantFrom.append(";gr=fghijk").c_str(),
			nullptr
		),
		parameter2,
		make_shared<BindListener>()
	);

	list<shared_ptr<Address>> participants;
	participants.push_back(Factory::get()->createAddress(participantFrom));
	participants.push_back(Factory::get()->createAddress(otherParticipantFrom));

	regEventCore->addListener(make_shared<RegistrationEvent::Server>());

	regEventCore->start();
	clientCore->start();

	auto chatRoomParams = clientCore->createDefaultChatRoomParams();
	chatRoomParams->enableGroup(true);
	auto chatRoom = clientCore->createChatRoom(chatRoomParams, me, "Chatroom with remote", participants);

	cout << "================= GNAP =================" << endl;

	/*shared_ptr<RegistrationEvent::Client> client = make_shared<RegistrationEvent::Client>(
		chatRoom,
		const_pointer_cast<const Address>(Factory::get()->createAddress(from))
	);
	client->subscribe();*/

	chatRoom->addParticipant(Factory::get()->createAddress(participantFrom));

	for (shared_ptr<Participant> participant : chatRoom->getParticipants()){
		cout << "HOY HOY PARTICIPANT " << participant->getAddress()->asString() << endl;

		for (auto device : participant->getDevices()){
			cout << "HOY HOY DEVICE " << device->getName() << endl;
		}
	}

	while (1/*!client->notifyReceived*/) {
		clientCore->iterate();
		regEventCore->iterate();
		su_root_step(a->getRoot(), 100);
	}

	/*for (auto participant : chatRoom->getParticipants()){
		cout << "HOY HOY PARTICIPANT " << participant->getAddress()->asString() << endl;

		for (auto device : participant->getDevices()){
			cout << "HOY HOY DEVICE " << device->getName() << endl;
		}
	}*/
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
