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

#include "regevent-server.hh"

#include "flexisip/configmanager.hh"
#include "linphone++/factory.hh"
#include "linphone++/transports.hh"
#include "linphone/misc.h"
#include "registration-events/server.hh"
#include "utils/client-core.hh"

using namespace std;

namespace flexisip::tester {

RegEventServer::RegEventServer(const std::shared_ptr<RegistrarDb>& registrarDb) {
	mCore = tester::minimalCore();

	const auto& transports = mCore->getTransports();
	transports->setUdpPort(LC_SIP_TRANSPORT_DONTBIND);
	transports->setTcpPort(LC_SIP_TRANSPORT_RANDOM);
	transports->setTlsPort(LC_SIP_TRANSPORT_DONTBIND);
	transports->setDtlsPort(LC_SIP_TRANSPORT_DONTBIND);

	mCore->addListener(make_shared<RegistrationEvent::Server::Application>(registrarDb));
	mCore->setTransports(transports);
	mCore->start();
}

RegEventServer::~RegEventServer() {
	if (mCore) mCore->stop();
}

SipUri RegEventServer::getTransport() const {
	return SipUri{"sip:127.0.0.1:" + to_string(mCore->getTransportsUsed()->getTcpPort()) + ";transport=tcp"};
}

std::shared_ptr<linphone::Core> RegEventServer::getCore() const {
	return mCore;
}

} // namespace flexisip::tester