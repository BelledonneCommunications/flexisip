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
	cTransport->setTcpPort(0);
	cTransport->setUdpPort(0);
	cTransport->setTlsPort(0);
	cTransport->setDtlsPort(0);

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
	auto configLinphone = Factory::get()->createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", 1);
	configLinphone->setString("storage", "backend", config->get<ConfigString>("database-backend")->read());
	configLinphone->setString("storage", "uri", config->get<ConfigString>("database-connection-string")->read());
	this->mCore = Factory::get()->createCoreWithConfig(nullptr, configLinphone);
	this->mCore->setConferenceFactoryUri(config->get<ConfigString>("conference-factory-uri")->read());
	this->mCore->setTransports(cTransport);

	shared_ptr<Address> addrProxy = Factory::get()->createAddress(this->mCore->getConferenceFactoryUri());
	shared_ptr<ProxyConfig> proxy = this->mCore->createProxyConfig();
	proxy->setIdentityAddress(addrProxy);
	proxy->setRoute(config->get<ConfigString>("outbound-proxy")->read());
	proxy->setServerAddr(config->get<ConfigString>("outbound-proxy")->read());
	proxy->enableRegister(FALSE);
	this->mCore->addProxyConfig(proxy);
	this->mCore->setDefaultProxyConfig(proxy);
	this->mCore->enableConferenceServer(TRUE); // duplicate?
}

void ConferenceServer::_run() {
	bctbx_sleep_ms(100);
	this->mCore->iterate();
}

void ConferenceServer::_stop() {
}

SofiaAutoHome ConferenceServer::mHome;

void ConferenceServer::bindConference() {
	class fakeListener : public ContactUpdateListener {
		void onRecordFound(Record *r) {}
		void onError() {}
		void onInvalid() {}
		void onContactUpdated(const std::shared_ptr<ExtendedContact> &ec) {
			SLOGD << "ConferenceServer::ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}
	};
	shared_ptr<fakeListener> listener = make_shared<fakeListener>();
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	if (config != nullptr && config->get<ConfigBoolean>("enabled")->read()) {
		string transport_factory = config->get<ConfigString>("transport")->read();
		sip_contact_t *sipContact = sip_contact_make(mHome.home(), transport_factory.c_str());
		sip_contact_t *contactDomain = sip_contact_make(mHome.home(), config->get<ConfigString>("conference-factory-uri")->read().c_str());
		url_t *url = url_format(mHome.home(), "sip:%s", contactDomain->m_url->url_host);
		RegistrarDb::get()->bind(url, sipContact, "CONFERENCE", 0,
								 NULL, NULL, NULL, FALSE, std::numeric_limits<int>::max(), FALSE, 0,
								 listener);
	}
}

ConferenceServer::Init ConferenceServer::sStaticInit;

ConferenceServer::Init::Init() {
	ConfigItemDescriptor items[] = {
		{Boolean, "enabled", "Enable conference server", "true"},
		{String, "transport",
			"uri where the conference server must listen.",
			"<sip:127.0.0.1:6064;transport=tcp>"},
		{String, "conference-factory-uri",
			"uri where the client must ask to create a conference.",
			"sip:conference-factory@sip1.linphone.org"},
		{String, "outbound-proxy",
			"",
			"sip:127.0.0.1:5060;transport=tcp"},
		{String, "database-backend",
			"Choose the type of backend that linphone will use for the connection.\n"
			"Depending on your Soci package and the modules you installed, the supported databases are:"
			"`mysql`, `sqlite3`",
			"mysql"},
		{String, "database-connection-string",
			"The configuration parameters of the backend.\n"
			"The basic format is \"key=value key2=value2\". For a mysql backend, this "
			"is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
			"Please refer to the Soci documentation of your backend, for instance: "
			"http://soci.sourceforge.net/doc/3.2/backends/mysql.html"
			"http://soci.sourceforge.net/doc/3.2/backends/sqlite3.html",
			"db='mydb' user='myuser' password='mypass' host='myhost.com'"},
		config_item_end};
		GenericStruct *s = new GenericStruct("conference-server", "Flexisip conference server parameters.", 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}
