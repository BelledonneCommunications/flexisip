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

#include "test-conference-server.hh"

#include <cstdlib>
#include <list>
#include <string>
#include <tuple>

#include "conference/conference-server.hh"
#include "eventlogs/writers/event-log-writer.hh" // IWYU pragma: keep
#include "flexisip/utils/sip-uri.hh"
#include "linphone/misc.h"

using namespace std;

namespace flexisip::tester {

TestConferenceServer::TestConferenceServer(const Server& proxy)
    : TestConferenceServer(*proxy.getAgent(), proxy.getConfigManager(), proxy.getRegistrarDb()) {
}
TestConferenceServer::TestConferenceServer(const Agent& agent,
                                           const std::shared_ptr<ConfigManager>& cfg,
                                           const std::shared_ptr<RegistrarDb>& registrarDb)
    : mRoot(agent.getRoot()),
      mConfServer(make_shared<PatchedConferenceServer>(agent.getPreferredRoute(), agent.getRoot(), cfg, registrarDb)) {
	mConfServer->getServerConf()
	    .get<ConfigString>("outbound-proxy")
	    ->set(cfg->getRoot()->get<GenericStruct>("global")->get<ConfigStringList>("transports")->read().front());
	mConfServer->init();
}

TestConferenceServer::~TestConferenceServer() {
	// Stopping the conference-server properly.
	std::ignore = mConfServer->stop();
	mConfServer.reset();
	mRoot->step(200ms);
}

void TestConferenceServer::clearLocalDomainList() {
	const_cast<std::list<std::string>&>(mConfServer->getLocalDomains()).clear();
}

void TestConferenceServer::PatchedConferenceServer::bindAddresses() {
	const auto& core = getCore();
	const auto& transports = core->getTransports();
	transports->setTcpPort(LC_SIP_TRANSPORT_RANDOM);
	core->setTransports(transports);
	mTransport = mTransport.replacePort(std::to_string((core->getTransportsUsed()->getTcpPort())));
	mConfigManager->getRoot()
	    ->get<GenericStruct>("conference-server")
	    ->get<ConfigString>("transport")
	    ->set(mTransport.str());

	ConferenceServer::bindAddresses();
}

} // namespace flexisip::tester
