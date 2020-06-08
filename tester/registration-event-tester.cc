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

#include "conference/registration-events/client-listener.hh"
#include "conference/registration-events/server-listener.hh"

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

	su_root_t *root = NULL;
	shared_ptr<Agent> a = make_shared<Agent>(root);
	Agent *agent = a->getAgent();


	class BindListener : public ContactUpdateListener {
	public:
		BindListener() {}
		void onRecordFound(const shared_ptr<Record> &r) override {}
		void onError() override {}
		void onInvalid() override {}
		void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) override {}
	};

	GenericManager *cfg = GenericManager::get();
	cfg->load("/flexisip.conf");
	agent->loadConfig(cfg);

	// Fill the RegistrarDB
	const char* from = "sip:test@test.com";
	string uuid = "12345";

	auto msg = nta_msg_create(agent->getSofiaAgent(), 0);
	msg_header_add_dup(
		msg,
		nullptr,
		reinterpret_cast<msg_header_t*>(sip_request_make(msg_home(msg), "MESSAGE sip:abcd SIP/2.0\r\n"))
	);

	BindingParameters parameter;
	parameter.globalExpire = 0;

	// We forge a fake SIP message
	auto sip = sip_object(msg);
	sip->sip_from = sip_from_create(msg_home(msg), (url_string_t *)from);
	sip->sip_contact = sip_contact_create(
		msg_home(msg),
		(url_string_t *)from, string("+sip.instance=").append(uuid).c_str(),
		nullptr
	);
	sip->sip_call_id = sip_call_id_make(msg_home(msg), "foobar");

	auto listener = make_shared<BindListener>();

	RegistrarDb::get()->bind(sip, parameter, listener);

	shared_ptr<ServerListener> serverLister = make_shared<ServerListener>();
	serverCore->addListener(serverLister);

	shared_ptr<ClientListener> clientListener = make_shared<ClientListener>();
	clientCore->addListener(clientListener);

	serverCore->start();
	clientCore->start();


	std::shared_ptr<Address> resource = Factory::get()->createAddress(serverCore->getIdentity());
	clientListener->subscribe(clientCore, resource);

	while (!clientListener->notifyReceived) {
		clientCore->iterate();
		serverCore->iterate();
		usleep(100000);
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
