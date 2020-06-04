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

	/*su_root_t *root = NULL;
	shared_ptr<Agent> a = make_shared<Agent>(root);
	Agent *agent = a->getAgent();

	GenericManager *cfg = GenericManager::get();
	cfg->getGlobal()->get<ConfigValue>("use-global-domain")->setDefault("false");
	agent->loadConfig(cfg);

	RegistrarDb::initialize(agent);*/

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
