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

#include <sstream>

#include <belle-sip/utils.h>

#include <flexisip/configmanager.hh>
#include <flexisip/flexisip-version.h>

#include "conference-address-generator.hh"
#include "conference-server.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {

sofiasip::Home ConferenceServer::mHome;
ConferenceServer::Init ConferenceServer::sStaticInit;

ConferenceServer::ConferenceServer (
	const string &path,
	su_root_t *root
) : ServiceServer(root), mPath(path), mSubscriptionHandler(*this) {}

ConferenceServer::~ConferenceServer () {}


void ConferenceServer::_init () {
	// Set config, transport, create core, etc
	shared_ptr<linphone::Transports> cTransport = linphone::Factory::get()->createTransports();
	cTransport->setTcpPort(0);
	cTransport->setUdpPort(0);
	cTransport->setTlsPort(0);
	cTransport->setDtlsPort(0);

	// Flexisip config
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	mTransport = config->get<ConfigString>("transport")->read();
	if (mTransport.length() > 0) {
		sofiasip::Home mHome;
		url_t *urlTransport = url_make(mHome.home(), mTransport.c_str());
		if (urlTransport != nullptr && mTransport.at(0) != '<') {
			int port;
			istringstream istr;
			istr.str(urlTransport->url_port);
			istr >> port;
			cTransport->setTcpPort(port);
		} else {
			LOGF("ConferenceServer: Your configured conference transport(\"%s\") is not an URI.\nIf you have \"<>\" in your transport, remove them.", mTransport.c_str());
		}
	}
	mCheckCapabilities = config->get<ConfigBoolean>("check-capabilities")->read();

	// Core
	shared_ptr<linphone::Config> configLinphone = linphone::Factory::get()->createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", 1);
	configLinphone->setBool("misc", "enable_one_to_one_chat_room", config->get<ConfigBoolean>("enable-one-to-one-chat-room")->read());
	configLinphone->setString("storage", "backend", config->get<ConfigString>("database-backend")->read());
	configLinphone->setString("storage", "uri", config->get<ConfigString>("database-connection-string")->read());
	mCore = linphone::Factory::get()->createCoreWithConfig(configLinphone, nullptr);
	mCore->setUserAgent("Flexisip-conference", FLEXISIP_GIT_VERSION);
	mCore->addListener(shared_from_this());
	mCore->enableConferenceServer(true);
	mCore->setTransports(cTransport);

	string conferenceFactoryUri = config->get<ConfigString>("conference-factory-uri")->read();
	shared_ptr<linphone::Address> addrProxy = linphone::Factory::get()->createAddress(conferenceFactoryUri);
	shared_ptr<linphone::ProxyConfig> proxy = mCore->createProxyConfig();
	proxy->setIdentityAddress(addrProxy);
	proxy->setRoute(config->get<ConfigString>("outbound-proxy")->read());
	proxy->setServerAddr(config->get<ConfigString>("outbound-proxy")->read());
	proxy->enableRegister(false);
	proxy->setConferenceFactoryUri(conferenceFactoryUri);
	mCore->addProxyConfig(proxy);
	mCore->setDefaultProxyConfig(proxy);

	linphone::Status err = mCore->start();
	if (err == -2) LOGF("Linphone Core couldn't start because the connection to the database has failed");
	if (err < 0) LOGF("Linphone Core starting failed");

	RegistrarDb::get()->addStateListener(shared_from_this());
	if (RegistrarDb::get()->isWritable())
		bindAddresses();
}

void ConferenceServer::_run () {
	mCore->iterate();
}

void ConferenceServer::_stop () {
	mCore->removeListener(shared_from_this());
	RegistrarDb::get()->removeStateListener(shared_from_this());
}

void ConferenceServer::onRegistrarDbWritable (bool writable) {
	if (writable)
		bindAddresses();
}

void ConferenceServer::onChatRoomStateChanged (
	const shared_ptr<linphone::Core> &lc,
	const shared_ptr<linphone::ChatRoom> &cr,
	linphone::ChatRoom::State state
) {
	if (state == linphone::ChatRoom::State::Instantiated) {
		mChatRooms.push_back(cr);
		cr->addListener(shared_from_this());
	} else if (state == linphone::ChatRoom::State::Deleted) {
		cr->removeListener(shared_from_this());
		mChatRooms.remove(cr);
	}
}

void ConferenceServer::onConferenceAddressGeneration (const shared_ptr<linphone::ChatRoom> & cr) {
	shared_ptr<linphone::Config> config = mCore->getConfig();
	string uuid = config->getString("misc", "uuid", "");
	shared_ptr<linphone::Address> confAddr = linphone::Factory::get()->createAddress(
		mCore->getDefaultProxyConfig()->getConferenceFactoryUri()
	);
	shared_ptr<ConferenceAddressGenerator> generator = make_shared<ConferenceAddressGenerator>(
		cr,
		confAddr,
		uuid,
		mPath,
		this
	);
	generator->run();
}

void flexisip::ConferenceServer::onParticipantRegistrationSubscriptionRequested (
	const shared_ptr<linphone::ChatRoom> &cr,
	const shared_ptr<const linphone::Address> &participantAddr
) {
	mSubscriptionHandler.subscribe(cr, participantAddr);
}

void flexisip::ConferenceServer::onParticipantRegistrationUnsubscriptionRequested (
	const shared_ptr<linphone::ChatRoom> &cr,
	const shared_ptr<const linphone::Address> &participantAddr
) {
	mSubscriptionHandler.unsubscribe(cr, participantAddr);
}

void flexisip::ConferenceServer::bindAddresses () {
	if (mAddressesBound)
		return;

	// Bind the conference factory address in the registrar DB
	bindConference();

	// Binding loaded chat room
	for (const auto &chatRoom : mCore->getChatRooms()) {
		if (chatRoom->getPeerAddress()->getUriParam("gr").empty()){
			LOGE("Skipping chatroom %s with no gruu parameter.", chatRoom->getPeerAddress()->asString().c_str());
			continue;
		}
		bindChatRoom(chatRoom->getPeerAddress()->asStringUriOnly(), mTransport, chatRoom->getPeerAddress()->getUriParam("gr"), nullptr);
	}

	mAddressesBound = true;
}

void flexisip::ConferenceServer::bindConference() {
	class FakeListener : public ContactUpdateListener {
		void onRecordFound(const std::shared_ptr<Record> &r) override {}
		void onError() override {}
		void onInvalid() override {}
		void onContactUpdated(const shared_ptr<ExtendedContact> &ec) override {
			SLOGD << "ConferenceServer: ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}
	};
	shared_ptr<FakeListener> listener = make_shared<FakeListener>();
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	if (config && config->get<ConfigBoolean>("enabled")->read()) {
		auto conferenceFactoryUriSetting = config->get<ConfigString>("conference-factory-uri");
		auto conferenceFactoryUri = conferenceFactoryUriSetting->read();
		if (conferenceFactoryUri.empty()) {
			LOGF("'%s' parameter must be set!", conferenceFactoryUriSetting->getCompleteName().c_str());
		}
		try {
			BindingParameters parameter;
			sip_contact_t* sipContact = sip_contact_create(mHome.home(),
				reinterpret_cast<const url_string_t*>(url_make(mHome.home(), mTransport.c_str())), nullptr);
			SipUri from(conferenceFactoryUri);

			parameter.callId = "CONFERENCE";
			parameter.path = mPath;
			parameter.globalExpire = numeric_limits<int>::max();
			parameter.alias = false;
			parameter.version = 0;

			RegistrarDb::get()->bind(
				from,
				sipContact,
				parameter,
				listener
			);
		} catch (const sofiasip::InvalidUrlError &e) {
			LOGF("'conference-server' value isn't a SIP URI [%s]", conferenceFactoryUri.c_str());
		}
	}
}

void ConferenceServer::bindChatRoom (
	const string &bindingUrl,
	const string &contact,
	const string &gruu,
	const shared_ptr<ContactUpdateListener> &listener
) {
	BindingParameters parameter;

	sip_contact_t* sipContact = sip_contact_create(mHome.home(),
		reinterpret_cast<const url_string_t*>(url_make(mHome.home(), contact.c_str())),
		su_strdup(mHome.home(), ("+sip.instance=" + UriUtils::grToUniqueId(gruu) ).c_str()), nullptr);

	parameter.callId = gruu;
	parameter.path = mPath;
	parameter.globalExpire = numeric_limits<int>::max();
	parameter.alias = false;
	parameter.version = 0;
	parameter.withGruu = true;

	RegistrarDb::get()->bind(
		SipUri(bindingUrl),
		sipContact,
		parameter,
		listener
	);
}

ConferenceServer::Init::Init() {
	ConfigItemDescriptor items[] = {
		{
			Boolean,
			"enabled",
			"Enable conference server", /* Do we need this ? The systemd enablement should be sufficient. */
			"true"
		},
		{
			String,
			"transport",
			"uri where the conference server must listen.",
			"sip:127.0.0.1:6064;transport=tcp"
		},
		{
			String,
			"conference-factory-uri",
			"uri where the client must ask to create a conference. For example: 'sip:conference-factory@sip.linphone.org'.",
			""
		},
		{
			Boolean,
			"enable-one-to-one-chat-room",
			"Whether one-to-one chat room creation is allowed or not.",
			"true"
		},
		{
			String,
			"outbound-proxy",
			"",
			"sip:127.0.0.1:5060;transport=tcp"
		},
		{
			String,
			"database-backend",
			"Choose the type of backend that linphone will use for the connection.\n"
			"Depending on your Soci package and the modules you installed, the supported databases are:"
			"`mysql`, `sqlite3`",
			"mysql"
		},
		{
			String,
			"database-connection-string",
			"The configuration parameters of the backend.\n"
			"The basic format is \"key=value key2=value2\". For a mysql backend, this "
			"is a valid config: \"db=mydb user=user password='pass' host=myhost.com\".\n"
			"Please refer to the Soci documentation of your backend, for instance: "
			"http://soci.sourceforge.net/doc/3.2/backends/mysql.html"
			"http://soci.sourceforge.net/doc/3.2/backends/sqlite3.html",
			"db='mydb' user='myuser' password='mypass' host='myhost.com'"
		},
		{
			Boolean,
			"check-capabilities",
			"Whether the conference server shall check device capabilities before inviting them to a session.\n"
			"The capability check is currently limited to Linphone client that put a +org.linphone.specs contact parameter"
			" in order to indicate whether they support group chat and secured group chat.",
			"true"
		},
		config_item_end
	};

	GenericStruct *s = new GenericStruct("conference-server", "Flexisip conference server parameters. "
		"The flexisip conference server is a user-agent that handles session-based chat (yes, text only at this time). "
		"It requires a mysql database in order to persisently store chatroom state (participants and their devices). "
		"It will use the Registrar backend (see section module::Registrar) to discover devices (or client instances) "
		"of each participant."
	, 0);
	GenericManager::get()->getRoot()->addChild(s);
	s->addChildrenValues(items);
}

} // namespace flexisip
