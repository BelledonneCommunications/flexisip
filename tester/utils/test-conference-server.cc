/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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

TestConferenceServer::TestConferenceServer(const Agent& agent)
    : mConfServer(make_shared<PatchedConferenceServer>(agent.getPreferredRoute(), agent.getRoot())) {
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
	GenericManager::get()
	    ->getRoot()
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
