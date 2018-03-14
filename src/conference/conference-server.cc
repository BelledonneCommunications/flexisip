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


void ParticipantRegistrationSubscription::onContactRegistered (const string &key, const string &uid) {
	shared_ptr<linphone::Address> deviceAddress = mParticipantAddress->clone();
	string gruu = uid;
	gruu = gruu.substr(gruu.find("\"<") + strlen("\"<"));
	gruu = gruu.substr(0, gruu.find(">"));
	deviceAddress->setUriParam("gr", gruu);
	mChatRoom->addParticipantDevice(mParticipantAddress, deviceAddress);
}


string ParticipantRegistrationSubscriptionHandler::getKey (const shared_ptr<const linphone::Address> &address) {
	return address->getUsername() + "@" + address->getDomain();
}

void ParticipantRegistrationSubscriptionHandler::subscribe (
	const shared_ptr<linphone::ChatRoom> &chatRoom,
	const shared_ptr<const linphone::Address> &address
) {
	string key = getKey(address);
	auto subscription = make_shared<ParticipantRegistrationSubscription>(address, chatRoom);
	mSubscriptions[key] = subscription;
	RegistrarDb::get()->subscribe(key, subscription);
}

void ParticipantRegistrationSubscriptionHandler::unsubscribe (
	const shared_ptr<linphone::ChatRoom> &chatRoom,
	const shared_ptr<const linphone::Address> &address
) {
	string key = getKey(address);
	auto it = mSubscriptions.find(key);
	if (it != mSubscriptions.end() && (it->second->getChatRoom() == chatRoom)) {
		RegistrarDb::get()->unsubscribe(key, it->second);
		mSubscriptions.erase(it);
	}
}


ConferenceServer::ConferenceServer() : ServiceServer() {}

ConferenceServer::ConferenceServer(bool withThread, const string &path, su_root_t* root) : ServiceServer(withThread, root), mPath(path) {}

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
	mCore = linphone::Factory::get()->createCoreWithConfig(configLinphone, nullptr);
	mCore->setUserAgent("Flexisip-conference", VERSION);
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

	mCore->start();

	// Binding loaded chat room
	for (const auto& chatRoom : mCore->getChatRooms()) {
		bindChatRoom(chatRoom->getPeerAddress()->asStringUriOnly() , transport, chatRoom->getPeerAddress()->getUriParam("gr"), mPath, nullptr);
	}
}

void ConferenceServer::_run() {
	mCore->iterate();
	if (mWithThread) bctbx_sleep_ms(10);
}

void ConferenceServer::_stop() {}


void ConferenceServer::onChatRoomStateChanged(const shared_ptr<linphone::Core> & lc, const shared_ptr<linphone::ChatRoom> & cr, linphone::ChatRoom::State state) {
	if (state == linphone::ChatRoom::State::Instantiated) {
		mChatRooms.push_back(cr);
		cr->addListener(shared_from_this());
	}
	else if (state == linphone::ChatRoom::State::Deleted) {
		cr->removeListener(shared_from_this());
		mChatRooms.remove(cr);
	}
}

void ConferenceServer::onConferenceAddressGeneration(const shared_ptr<linphone::ChatRoom> & cr) {
	class ConferenceAddressGenerator : public ContactUpdateListener, public enable_shared_from_this<ConferenceAddressGenerator> {
	public:
		enum class State {
			Fetching,
			Binding
		};

		ConferenceAddressGenerator(const shared_ptr<linphone::ChatRoom> chatRoom,
			shared_ptr<linphone::Address> conferenceFactoryAddr, const string &uuid, const string &path)
		: mChatRoom(chatRoom), mConferenceAddr(conferenceFactoryAddr), mUuid(uuid), mPath(path) {}

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
					bindChatRoom(mConferenceAddr->asStringUriOnly(), config->get<ConfigString>("transport")->read(), mUuid, mPath, shared_from_this());
				}
			} else {
				const shared_ptr<ExtendedContact> ec = r->getExtendedContacts().front();
				string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
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
		string mPath;
	};

	shared_ptr<linphone::Config> config = mCore->getConfig();
	string uuid = config->getString("misc", "uuid", "");
	shared_ptr<linphone::Address> confAddr = linphone::Factory::get()->createAddress(mCore->getDefaultProxyConfig()->getConferenceFactoryUri());
	shared_ptr<ConferenceAddressGenerator> generator = make_shared<ConferenceAddressGenerator>(cr, confAddr, uuid, mPath);
	generator->generateAddress();
}

void ConferenceServer::onParticipantDeviceFetchRequested(const shared_ptr<linphone::ChatRoom> & cr, const shared_ptr<const linphone::Address> & participantAddr) {
	class ParticipantDevicesSearch : public ContactUpdateListener, public enable_shared_from_this<ParticipantDevicesSearch> {
	public:
		ParticipantDevicesSearch(const shared_ptr<linphone::ChatRoom> &cr, const shared_ptr<const linphone::Address> &uri) : mChatRoom(cr), mSipUri(uri) {}

		void searchDevices() {
			url_t *url = url_make(mHome.home(), mSipUri->asStringUriOnly().c_str());
			RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
		}
	private:
		SofiaAutoHome mHome;
		const shared_ptr<linphone::ChatRoom> mChatRoom;
		const shared_ptr<const linphone::Address> mSipUri;

		void onRecordFound(Record *r) {
			if (r) {
				list<shared_ptr<linphone::Address>> listDevices;
				for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
					string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
					shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
					if (!addr->getUriParam("gr").empty() && ec->getOrgLinphoneSpecs().find("groupchat") != string::npos) {
						shared_ptr<linphone::Address> gruuAddr = linphone::Factory::get()->createAddress(mSipUri->asStringUriOnly());
						gruuAddr->setUriParam("gr", addr->getUriParam("gr"));
						listDevices.push_back(gruuAddr);
					}
				}
				mChatRoom->setParticipantDevices(mSipUri, listDevices);
			}
		}
		void onError() {}
		void onInvalid() {}
		void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {}
	};
	shared_ptr<ParticipantDevicesSearch> search= make_shared<ParticipantDevicesSearch>(cr, participantAddr);
	search->searchDevices();
}

void ConferenceServer::onParticipantsCapabilitiesChecked(const shared_ptr<linphone::ChatRoom> & cr, const shared_ptr<const linphone::Address> &deviceAddr, const list<shared_ptr<linphone::Address> > & participantsAddr) {
	class ParticipantsCapabilitiesCheck : public ContactUpdateListener, public enable_shared_from_this<ParticipantsCapabilitiesCheck> {
	public:
		ParticipantsCapabilitiesCheck(const shared_ptr<linphone::ChatRoom> &cr, const shared_ptr<const linphone::Address> &deviceAddr, const list<shared_ptr<linphone::Address>> &list) : mChatRoom(cr), mDeviceAddr(deviceAddr), mParticipantsList(list) {
			mIterator = mParticipantsList.begin();
		}

		void checkParticipantsCapabilities() {
			url_t *url = url_make(mHome.home(), mIterator->get()->asStringUriOnly().c_str());
			RegistrarDb::get()->fetch(url, shared_from_this(), false, false);
		}
	private:
		SofiaAutoHome mHome;
		const shared_ptr<linphone::ChatRoom> mChatRoom;
		shared_ptr<const linphone::Address> mDeviceAddr;
		list<shared_ptr<linphone::Address>> mParticipantsList;
		list<shared_ptr<linphone::Address>> mParticipantsCompatibleList;
		list<shared_ptr<linphone::Address>>::iterator mIterator;

		void onRecordFound(Record *r) {
			if (r) {
				for (const shared_ptr<ExtendedContact> &ec : r->getExtendedContacts()) {
					string uri = ExtendedContact::urlToString(ec->mSipContact->m_url);
					shared_ptr<linphone::Address> addr = linphone::Factory::get()->createAddress(uri);
					if (!addr->getUriParam("gr").empty() && ec->getOrgLinphoneSpecs().find("groupchat") != string::npos) {
						mParticipantsCompatibleList.push_back(*mIterator);
						break;
					}
				}
			}
			mIterator++;
			if (mIterator != mParticipantsList.end()) {
				checkParticipantsCapabilities();
			} else {
				mChatRoom->addCompatibleParticipants(mDeviceAddr, mParticipantsCompatibleList);
			}
		}
		void onError() {}
		void onInvalid() {}
		void onContactUpdated(const shared_ptr<ExtendedContact> &ec) {}
	};
	shared_ptr<ParticipantsCapabilitiesCheck> search= make_shared<ParticipantsCapabilitiesCheck>(cr, deviceAddr, participantsAddr);
	search->checkParticipantsCapabilities();
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

void flexisip::ConferenceServer::bindConference(const string &path) {
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
		sip_path_t *bindingPath = nullptr;
		bindingPath = sip_path_format(mHome.home(), "<%s>", path.c_str());
		RegistrarDb::get()->bind(url, sipContact, "CONFERENCE", 0, bindingPath, nullptr, nullptr,
								 true, numeric_limits<int>::max(), false, 0, listener);
	}
}

void ConferenceServer::bindChatRoom(const string &bindingUrl, const string &contact, const string &gruu, const string &path, const shared_ptr< ContactUpdateListener >& listener) {

	url_t *url = url_make(mHome.home(), bindingUrl.c_str());
	sip_contact_t *sipContact = sip_contact_make(mHome.home(), contact.c_str());
	sip_contact_add_param(mHome.home(), sipContact, su_strdup(mHome.home(), ("+sip.instance=\"<" + gruu + ">\"").c_str()));
	url_param_add(mHome.home(), sipContact->m_url, ("gr=" + gruu).c_str());
	sip_supported_t *sipSupported = reinterpret_cast<sip_supported_t *>(sip_header_format(mHome.home(), sip_supported_class, "gruu"));
	sip_path_t *bindingPath = nullptr;
	bindingPath = sip_path_format(mHome.home(), "<%s>", path.c_str());
	RegistrarDb::get()->bind(url, sipContact, gruu.c_str(), 0, bindingPath, sipSupported,
							 nullptr, true, numeric_limits<int>::max(), false, 0, listener);
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
