/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include <linphone/misc.h>
#include <list>
#include <string>
#include <tuple>

#include "conference/conference-server.hh"
#include "eventlogs/writers/event-log-writer.hh" // IWYU pragma: keep
#include "flexisip/utils/sip-uri.hh"

using namespace std;

namespace flexisip {
namespace tester {

TestConferenceServer::TestConferenceServer(const Agent& agent,
                                           const std::shared_ptr<ConfigManager>& cfg,
                                           const std::shared_ptr<RegistrarDb>& registrarDb)
    : mConfServer(make_shared<PatchedConferenceServer>(agent.getPreferredRoute(), agent.getRoot(), cfg, registrarDb)) {
	mConfServer->init();
}

TestConferenceServer::~TestConferenceServer() {
	mConfServer->stop();
}

void TestConferenceServer::clearLocalDomainList() {
	const_cast<std::list<std::string>&>(mConfServer->getLocalDomains()).clear();
}

void TestConferenceServer::PatchedConferenceServer::bindAddresses() {
	const auto& core = getCore();
	const auto& transports = core->getTransports();
	transports->setTcpPort(LC_SIP_TRANSPORT_RANDOM);
	core->setTransports(transports);
	const auto port = std::to_string((core->getTransportsUsed()->getTcpPort()));
	const_cast<url_t*>(mTransport.get())->url_port = port.c_str();
	const auto newTransport = mTransport.str();
	mConfigManager->getRoot()
	    ->get<GenericStruct>("conference-server")
	    ->get<ConfigString>("transport")
	    ->set(newTransport);
	// `port` is destroyed at the end of the scope, which (probably) invalidates the `->url_port` char*.
	// Better to build `mTransport` anew
	mTransport = SipUri(newTransport);

	ConferenceServer::bindAddresses();
}

} // namespace tester
} // namespace flexisip
