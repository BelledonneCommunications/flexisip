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

using namespace std;
using namespace linphone;
using namespace flexisip;

static void basic() {
	shared_ptr<Core> clientCore = Factory::get()->createCore("","", nullptr);
	clientCore->getConfig()->setString("storage", "uri", "null");
	shared_ptr<Transports> transport = Factory::get()->createTransports();
	transport->setTcpPort(rand() %0x0FFF + 1014);
	clientCore->setTransports(transport);

	shared_ptr<Core> serverCore = Factory::get()->createCore("", "", nullptr);
	serverCore->getConfig()->setString("storage", "uri", "null");
	shared_ptr<Transports> serverTransport = Factory::get()->createTransports();
	serverTransport->setTcpPort(rand() %0x0FFF + 1014);
	serverCore->setTransports(serverTransport);

	// Agent initialisation

	su_root_t *root = su_root_create(NULL);
	shared_ptr<Agent> a = make_shared<Agent>(root);
	Agent *agent = a->getAgent();

	GenericManager *cfg = GenericManager::get();
	cfg->load("/flexisip.conf");
	agent->loadConfig(cfg);

	// Fill the RegistrarDB

	class BindListener : public ContactUpdateListener {
	public:
		void onRecordFound(const shared_ptr<Record> &r) override {}
		void onError() override {}
		void onInvalid() override {}
		void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) override {}
	};

	BindingParameters parameter;
	parameter.globalExpire = 1000;

	string from = serverCore->getIdentity();

	serverCore->addListener(make_shared<RegistrationEvent::Server>());
	shared_ptr<RegistrationEvent::Client> client = make_shared<RegistrationEvent::Client>(
		clientCore,
		Factory::get()->createAddress(from)
	);

	serverCore->start();
	clientCore->start();

	auto msg = nta_msg_create(agent->getSofiaAgent(), 0);
	client->subscribe();
	clientCore->addListener(client);

	// We forge a fake SIP message
	auto sip = sip_object(msg);
	sip->sip_from = sip_from_create(msg_home(msg), (url_string_t *)from.c_str());
	sip->sip_contact = sip_contact_create(
		msg_home(msg),
		(url_string_t *)from.c_str(),
		string("+sip.instance=").append("12345").c_str(),
		nullptr
	);
	sip->sip_user_agent = sip_user_agent_make(msg_home(msg), "Linphone (Debian) LinphoneCore");
	sip->sip_call_id = sip_call_id_make(msg_home(msg), "foobar");

	RegistrarDb::get()->bind(sip, parameter, make_shared<BindListener>());

	while (!client->notifyReceived) {
		clientCore->iterate();
		serverCore->iterate();
	}
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
