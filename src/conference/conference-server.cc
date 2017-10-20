/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2017  Belledonne Communications SARL.
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.
 
 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "conference-server.hh"

#include "configmanager.hh"

using namespace flexisip;
using namespace linphone;
using namespace std;

ConferenceServer::ConferenceServer() : ServiceServer() {
}

ConferenceServer::ConferenceServer(bool withThread) : ServiceServer(withThread) {
}

ConferenceServer::~ConferenceServer() {}

void ConferenceServer::_init() {
	// Set config, transport, create core, etc
	shared_ptr<Transports> cTransport = Factory::get()->createTransports();
	string transport = "";
	cTransport->setTcpPort(-1);

	// Flexisip config
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	transport = config->get<ConfigString>("transport")->read();
	if (transport.length() > 0) {
		SofiaAutoHome mHome;
		sip_contact_t *sipContact = sip_contact_make(mHome.home(), transport.c_str());
		if (sipContact->m_url->url_port != NULL) {
			int port;
			istringstream istr;
			istr.str(sipContact->m_url->url_port);
			istr >> port;
			cTransport->setTcpPort(port);
		}
	}

	// Core
	this->mCore = Factory::get()->createCore(nullptr, "", "");
	this->mCore->getConfig()->setBool("misc", "conference_server_enabled", 1);
	this->mCore->setTransports(cTransport);
}

void ConferenceServer::_run() {
	this->mCore->iterate();
}

void ConferenceServer::_stop() {
}

SofiaAutoHome ConferenceServer::mHome;

void ConferenceServer::bindConference() {
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	if (config != nullptr && config->get<ConfigBoolean>("enabled")->read()) {
		string transport_factory = config->get<ConfigString>("conference-factory-uri")->read();
		sip_contact_t *sipContact = sip_contact_make(mHome.home(), transport_factory.c_str());
		RegistrarDb::get()->bind(sipContact->m_url, sipContact, "CONFERENCE", 0,
								 NULL, NULL, NULL, TRUE, std::numeric_limits<int>::max(), FALSE, 0, NULL);
	}
}

ConferenceServer::Init ConferenceServer::sStaticInit;

ConferenceServer::Init::Init() {
	ConfigItemDescriptor items[] = {
		{Boolean, "enabled", "Enable conference server", "true"},
		{String, "transport",
			"uri where the conference server must listen.",
			"sip:127.0.0.1:6064"},
		{String, "conference-factory-uri",
			"uri where the client must ask to create a conference.",
			"sip:conference-factory@sip1.linphone.org"},
		config_item_end};
		GenericStruct *s = new GenericStruct("conference-server", "Flexisip conference server parameters.", 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}
