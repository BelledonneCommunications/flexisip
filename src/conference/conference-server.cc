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

#include "conference-server.hh"

#include "configmanager.hh"

using namespace flexisip;
using namespace std;


SofiaAutoHome ConferenceServer::mHome;
ConferenceServer::Init ConferenceServer::sStaticInit;


ConferenceServer::ConferenceServer() : ServiceServer() {}

ConferenceServer::ConferenceServer(bool withThread) : ServiceServer(withThread) {}

ConferenceServer::~ConferenceServer() {}


void ConferenceServer::_init() {
	// Set config, transport, create core, etc
	shared_ptr<linphone::Transports> cTransport = linphone::Factory::get()->createTransports();
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
		if (sipContact->m_url->url_port != nullptr) {
			int port;
			istringstream istr;
			istr.str(sipContact->m_url->url_port);
			istr >> port;
			cTransport->setTcpPort(port);
		}
	}

	// Core
	shared_ptr<linphone::Config> configLinphone = linphone::Factory::get()->createConfig("");
	configLinphone->setBool("misc", "conference_server_enabled", 1);
	configLinphone->setString("storage", "backend", config->get<ConfigString>("database-backend")->read());
	configLinphone->setString("storage", "uri", config->get<ConfigString>("database-connection-string")->read());
	mCore = linphone::Factory::get()->createCoreWithConfig(nullptr, configLinphone);
	mCore->addListener(shared_from_this());
	mCore->setConferenceFactoryUri(config->get<ConfigString>("conference-factory-uri")->read());
	mCore->enableConferenceServer(true);
	mCore->setTransports(cTransport);

	shared_ptr<linphone::Address> addrProxy = linphone::Factory::get()->createAddress(mCore->getConferenceFactoryUri());
	shared_ptr<linphone::ProxyConfig> proxy = mCore->createProxyConfig();
	proxy->setIdentityAddress(addrProxy);
	proxy->setRoute(config->get<ConfigString>("outbound-proxy")->read());
	proxy->setServerAddr(config->get<ConfigString>("outbound-proxy")->read());
	proxy->enableRegister(false);
	mCore->addProxyConfig(proxy);
	mCore->setDefaultProxyConfig(proxy);
}

void ConferenceServer::_run() {
	bctbx_sleep_ms(100);
	mCore->iterate();
}

void ConferenceServer::_stop() {}


void ConferenceServer::onChatRoomStateChanged(const shared_ptr<linphone::Core> & lc, const shared_ptr<linphone::ChatRoom> & cr, linphone::ChatRoomState state) {
	if (state == linphone::ChatRoomStateInstantiated)
		cr->setListener(shared_from_this());
}

void ConferenceServer::onConferenceAddressGeneration(const std::shared_ptr<linphone::ChatRoom> & cr) {
	class ConferenceAddressGenerator : public ContactUpdateListener, public enable_shared_from_this<ConferenceAddressGenerator> {
	public:
		enum class State {
			Fetching,
			Binding
		};

		ConferenceAddressGenerator(const shared_ptr<linphone::ChatRoom> chatRoom,
			shared_ptr<linphone::Address> conferenceFactoryAddr, const string &uuid)
			: mChatRoom(chatRoom), mConferenceAddr(conferenceFactoryAddr), mUuid(uuid) {}

		void generateAddress() {
			char token[17];
			ostringstream os;
			belle_sip_random_token(token, sizeof(token));
			os.str("");
			os << "chatroom-" << token;
			mConferenceAddr->setUsername(os.str());
			os.str("");
			os << "\"<urn:uuid:" << mUuid << ">\"";
			mConferenceAddr->setParam("+sip.instance", os.str());

			url_t *url = url_make(mHome.home(), mConferenceAddr->asStringUriOnly().c_str());
			RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
		}

	private:
		void onRecordFound(Record *r) {
			if (mState == State::Fetching) {
				if (r) {
					generateAddress();
				} else {
					mState = State::Binding;
					auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
					string transportFactory = config->get<ConfigString>("transport")->read();
					url_t *url = url_make(mHome.home(), mConferenceAddr->asStringUriOnly().c_str());
					sip_contact_t *sipContact = sip_contact_make(mHome.home(), transportFactory.c_str());
					url_param_add(mHome.home(), sipContact->m_url, ("gr=urn:uuid:" + mUuid).c_str());
					sip_supported_t *sipSupported = reinterpret_cast<sip_supported_t *>(sip_header_format(mHome.home(), sip_supported_class, "gruu"));
					RegistrarDb::get()->bind(url, sipContact, ("\"<urn:uuid:" + mUuid + ">\"").c_str(), 0, nullptr, sipSupported,
						nullptr, false, numeric_limits<int>::max(), false, 0, shared_from_this());
				}
			} else {
				const shared_ptr<ExtendedContact> ec = r->getExtendedContacts().front();
				string uri = ExtendedContact::urlToString(ec->mSipUri);
				shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
				shared_ptr<linphone::Address> gruuAddr = linphone::Factory::get()->createAddress(mConferenceAddr->asStringUriOnly());
				gruuAddr->setUriParam("gr", addr->getUriParam("gr"));
				mChatRoom->setConferenceAddress(gruuAddr);
			}
		}
		void onError() {}
		void onInvalid() {}
		void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {}

		const shared_ptr<linphone::ChatRoom> mChatRoom;
		shared_ptr<linphone::Address> mConferenceAddr;
		string mUuid;
		SofiaAutoHome mHome;
		State mState = State::Fetching;
	};

	shared_ptr<linphone::Config> config = mCore->getConfig();
	string uuid = config->getString("misc", "uuid", "");
	shared_ptr<linphone::Address> confAddr = linphone::Factory::get()->createAddress(mCore->getConferenceFactoryUri());
	shared_ptr<ConferenceAddressGenerator> generator = make_shared<ConferenceAddressGenerator>(cr, confAddr, uuid);
	generator->generateAddress();
}

void ConferenceServer::onParticipantDeviceFetched(const std::shared_ptr<linphone::ChatRoom> & cr, const std::shared_ptr<const linphone::Address> & participantAddr) {
	class ParticipantDevicesSearch : public ContactUpdateListener, public enable_shared_from_this<ParticipantDevicesSearch> {
	public:
		ParticipantDevicesSearch(const std::shared_ptr<linphone::ChatRoom> &cr, const std::shared_ptr<const linphone::Address> &uri) : mChatRoom(cr), mSipUri(uri) {}

		void searchingDevices() {
			url_t *url = url_make(mHome.home(), mSipUri->asStringUriOnly().c_str());
			RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
		}
	private:
		SofiaAutoHome mHome;
		const shared_ptr<linphone::ChatRoom> mChatRoom;
		const std::shared_ptr<const linphone::Address> mSipUri;

		void onRecordFound(Record *r) {
			if (r) {
				string participantStringUri = ExtendedContact::urlToString(r->getExtendedContacts().front()->mSipUri);
				shared_ptr<linphone::Address> participantAddr = linphone::Factory::get()->createAddress(participantStringUri);
				list<string> listDevices;
				for (const shared_ptr<ExtendedContact> ec : r->getExtendedContacts()) {
					string uri = ExtendedContact::urlToString(ec->mSipUri);
					shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
					if (addr->getUriParam("gr").length() > 0) {
						shared_ptr<linphone::Address> gruuAddr = linphone::Factory::get()->createAddress(mSipUri->asStringUriOnly());
						gruuAddr->setUriParam("gr", addr->getUriParam("gr"));
						listDevices.push_back(addr->asString());
					}
				}
				mChatRoom->setParticipantDevices(participantAddr, listDevices);
			}
		}
		void onError() {}
		void onInvalid() {}
		void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {}
	};
	shared_ptr<ParticipantDevicesSearch> search= make_shared<ParticipantDevicesSearch>(cr, participantAddr);
	search->searchingDevices();
}

void ConferenceServer::bindConference() {
	class fakeListener : public ContactUpdateListener {
		void onRecordFound(Record *r) {}
		void onError() {}
		void onInvalid() {}
		void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {
			SLOGD << "ConferenceServer: ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}
	};
	shared_ptr<fakeListener> listener = make_shared<fakeListener>();
	auto config = GenericManager::get()->getRoot()->get<GenericStruct>("conference-server");
	if (config != nullptr && config->get<ConfigBoolean>("enabled")->read()) {
		string transportFactory = config->get<ConfigString>("transport")->read();
		sip_contact_t *sipContact = sip_contact_make(mHome.home(), transportFactory.c_str());
		url_t *url = url_make(mHome.home(), config->get<ConfigString>("conference-factory-uri")->read().c_str());
		RegistrarDb::get()->bind(url, sipContact, "CONFERENCE", 0,
			nullptr, nullptr, nullptr, false, numeric_limits<int>::max(), false, 0, listener);
	}
}

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
