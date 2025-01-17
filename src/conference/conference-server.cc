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

#include "conference-server.hh"

#include <fstream>

#include <belle-sip/utils.h>
#include <sofia-sip/sip_header.h>

#include <flexisip/configmanager.hh>
#include <flexisip/flexisip-version.h>

#include "conference-address-generator.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registration-events/client.hh"
#include "utils/media/media.hh"
#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;

namespace flexisip {

sofiasip::Home ConferenceServer::mHome;

void ConferenceServer::_init() {
	string bindAddress{};

	// Set config, transport, create core, etc
	auto cTransport = Factory::get()->createTransports();
	cTransport->setTcpPort(0);
	cTransport->setUdpPort(0);
	cTransport->setTlsPort(0);
	cTransport->setDtlsPort(0);

	// Flexisip config
	const auto* config = mConfigManager->getRoot()->get<GenericStruct>("conference-server");
	try {
		mTransport = SipUri{config->get<ConfigString>("transport")->read()};
		if (mTransport.empty()) throw sofiasip::InvalidUrlError{"", "empty URI"};

		bindAddress = mTransport.getHost();

		const auto& portStr = mTransport.getPort();
		auto port = !portStr.empty() ? stoi(portStr) : 5060;
		cTransport->setTcpPort(port);
	} catch (const sofiasip::InvalidUrlError& e) { // thrown by SipUri constructor and when mTransport is empty
		LOGF("ConferenceServer: Your configured conference transport(\"%s\") is not an URI.\nIf you have \"<>\" in "
		     "your transport, remove them.",
		     e.getUrl().c_str());
	}
	mCheckCapabilities = config->get<ConfigBoolean>("check-capabilities")->read();
	mStateDir = config->get<ConfigString>("state-directory")->read();

	/* Read enabled media types (audio, video, text) */
	auto mediaTypes = config->get<ConfigStringList>("supported-media-types")->read();
	if (find(mediaTypes.begin(), mediaTypes.end(), "audio") != mediaTypes.end()) mMediaConfig.audioEnabled = true;
	if (find(mediaTypes.begin(), mediaTypes.end(), "video") != mediaTypes.end()) mMediaConfig.videoEnabled = true;
	if (find(mediaTypes.begin(), mediaTypes.end(), "text") != mediaTypes.end()) mMediaConfig.textEnabled = true;
	if (mMediaConfig.audioEnabled == false && mMediaConfig.videoEnabled == false && mMediaConfig.textEnabled == false) {
		LOGF("ConferenceServer: no media types enabled. Check configuration file.");
	}

	// Core
	auto configLinphone = Factory::get()->createConfig("");
	configLinphone->setString("sip", "bind_address", bindAddress);
	configLinphone->setBool("misc", "conference_server_enabled", true);
	configLinphone->setBool("misc", "enable_one_to_one_chat_room",
	                        config->get<ConfigBoolean>("enable-one-to-one-chat-room")->read());
	configLinphone->setBool("misc", "empty_chat_room_deletion",
	                        config->get<ConfigBoolean>("empty-chat-room-deletion")->read());

	if (mMediaConfig.textEnabled) {
		string dbUri = config->get<ConfigString>("database-connection-string")->read();
		if (dbUri.empty())
			LOGF("ConferenceServer: database-connection-string is not set. It is mandatory for handling text "
			     "conferences.");
		configLinphone->setInt("misc", "hide_empty_chat_rooms", 0);
		configLinphone->setInt("misc", "hide_chat_rooms_from_removed_proxies", 0);
		configLinphone->setString("storage", "backend", config->get<ConfigString>("database-backend")->read());
		configLinphone->setString("storage", "uri", dbUri);
	} else {
		configLinphone->setString("storage", "uri", "null");
	}
	configLinphone->setString("storage", "call_logs_db_uri", "null");
	configLinphone->setString("storage", "zrtp_secrets_db_uri", "null");
	configLinphone->setString("lime", "x3dh_db_path", ":memory:");

	configLinphone->setInt("misc", "max_calls", 1000);
	configLinphone->setBool("sip", "reject_duplicated_calls", false);
	configLinphone->setInt("sound", "conference_rate", 48000);
	configLinphone->setBool("rtp", "symmetric", true);
	configLinphone->setBool("rtp", "rtcp_enabled", true);
	configLinphone->setBool("rtp", "rtcp_mux", true);
	configLinphone->setBool("video", "dont_check_codecs", true);
	configLinphone->setBool("net", "enable_nat_helper",
	                        false); // to make sure contact address is not fixed by belle-sip

	auto mediaEngine = config->get<ConfigString>("media-engine-type")->read();
	if (mediaEngine != "mixer" && mediaEngine != "sfu") {
		LOGF("ConferenceServer: media-engine-type is not correctly set. Check configuration file.");
	}

	if (mediaEngine == "mixer") {
		// In mixer mode we set the audio conference to Mixer mode (0) and video conference to RouterPayload mode (1)
		configLinphone->setInt("sound", "conference_mode", 0);
		configLinphone->setInt("video", "conference_mode", 1);
	} else {
		// In SFU mode we set the audio and video conferences to RouterFullPacket mode (2)
		configLinphone->setInt("sound", "conference_mode", 2);
		configLinphone->setInt("video", "conference_mode", 2);
	}

	string uuid = readUuid();
	if (!uuid.empty()) configLinphone->setString("misc", "uuid", uuid);

	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);

	mCore = linphone::Factory::get()->createCoreWithConfig(configLinphone, nullptr);

	mCore->setInCallTimeout(
	    chrono::duration_cast<seconds>(config->get<ConfigDuration<chrono::seconds>>("call-timeout")->read()).count());
	mCore->enableRtpBundle(true);
	mCore->enableEchoCancellation(false);

	mCore->setUserAgent("Flexisip-conference", FLEXISIP_GIT_VERSION);
	mCore->addListener(shared_from_this());
	mCore->enableConferenceServer(true);
	mCore->setTransports(cTransport);

	// Make LinphoneCore to slice incoming LIME multipart messages in order
	// each forwarded message contains only one encrypted message instead
	// of having the encrypted version for each recipient.
	mCore->enableLimeX3Dh(true);

	const int audioPortMin = config->get<ConfigIntRange>("audio-port")->readMin();
	const int audioPortMax = config->get<ConfigIntRange>("audio-port")->readMax();
	setMediaPort(audioPortMin, audioPortMax, *mCore, &linphone::Core::setAudioPort, &linphone::Core::setAudioPortRange);

	const int videoPortMin = config->get<ConfigIntRange>("video-port")->readMin();
	const int videoPortMax = config->get<ConfigIntRange>("video-port")->readMax();
	setMediaPort(videoPortMin, videoPortMax, *mCore, &linphone::Core::setVideoPort, &linphone::Core::setVideoPortRange);

	mCore->setUseFiles(true); // No sound card shall be used in calls.
	/*
	 * Let the conference server work with all liblinphone's default audio codec s(opus, speex, pcmu, pcma).
	 * enableSelectedCodecs(mCore->getAudioPayloadTypes(), {"opus", "speex"});
	 * We have to restrict for video because as of today only VP8 is supported.
	 */
	enableSelectedCodecs(mCore->getVideoPayloadTypes(), {"VP8"});

	string encryption = config->get<ConfigString>("encryption")->read();
	const auto encryptionMode = StringUtils::string2MediaEncryption(encryption);
	if (encryptionMode) {
		mCore->setMediaEncryption(*encryptionMode);
	}
	/* Create a directory for automatically generated DTLS-SRTP certificates */
	filesystem::path dtlsDir = getStateDir("dtls-srtp");
	ensureDirectoryCreated(dtlsDir);
	mCore->setUserCertificatesPath(dtlsDir);

	mCore->setVideoDisplayFilter("MSExtDisplay");

	// Enable ICE (with host candidates only) so that the relay service of the proxies is bypassed.
	shared_ptr<linphone::NatPolicy> natPolicy = mCore->createNatPolicy();
	natPolicy->enableIce(true);
	configureNatAddresses(natPolicy, config->get<ConfigStringList>("nat-addresses")->read());
	mCore->setNatPolicy(natPolicy);

	loadFactoryUris();

	auto outboundProxy = config->get<ConfigString>("outbound-proxy")->read();
	auto outboundProxyAddress = Factory::get()->createAddress(outboundProxy);
	if (!outboundProxyAddress) {
		LOGF("Invalid outbound-proxy value '%s'", outboundProxy.c_str());
	}
	bool defaultAccountSet = false;
	for (const auto& conferenceServerUris : mConfServerUris) {
		auto factoryUri = Factory::get()->createAddress(conferenceServerUris.first);
		auto accountParams = mCore->createAccountParams();

		if (!conferenceServerUris.second.empty()) {
			auto focusUri = Factory::get()->createAddress(conferenceServerUris.second);
			accountParams->setIdentityAddress(focusUri);
		} else {
			accountParams->setIdentityAddress(factoryUri);
		}
		accountParams->setServerAddress(outboundProxyAddress);
		accountParams->enableRegister(false);
		accountParams->enableOutboundProxy(true);
		accountParams->setConferenceFactoryUri(factoryUri->asString());
		auto account = mCore->createAccount(accountParams);
		// The default contact address is the identity address. It will be used if the connection to the REDIS server is
		// broken or the answer is very slow and a client calls a conference before onRecordFound() is called
		account->setContactAddress(accountParams->getIdentityAddress());
		mCore->addAccount(account);
		if (!defaultAccountSet) {
			defaultAccountSet = true;
			mCore->setDefaultAccount(account);
		}
		mLocalDomains.push_back(factoryUri->getDomain());
	}

	/* Get additional local domains */
	auto otherLocalDomains = config->get<ConfigStringList>("local-domains")->read();
	for (auto& domain : otherLocalDomains)
		mLocalDomains.emplace_back(std::move(domain));
	otherLocalDomains.clear();
	mLocalDomains.sort();
	mLocalDomains.unique();

	mRegEventClientFactory = make_shared<RegistrationEvent::ClientFactory>(mCore);

	Status err = mCore->start();
	if (err == -2) LOGF("Linphone Core couldn't start because the connection to the database has failed");
	if (err < 0) LOGF("Linphone Core starting failed");

	if (uuid.empty()) {
		// In case no uuid was set in persistent state directory, take the one randomly choosen by Liblinphone.
		writeUuid(configLinphone->getString("misc", "uuid", ""));
	} else if (configLinphone->getString("misc", "uuid", "") != uuid) {
		LOGF("Unconsistent uuid");
	}

	mRegistrarDb->addStateListener(shared_from_this());
	if (mRegistrarDb->isWritable()) {
		bindAddresses();
	}
}

void ConferenceServer::configureNatAddresses(shared_ptr<linphone::NatPolicy> natPolicy, const list<string>& addresses) {
	int err;
	bool ipv4_set = false;
	bool ipv6_set = false;
	for (const auto& addr : addresses) {
		struct addrinfo* res = nullptr;
		struct addrinfo* ai_it = nullptr;
		struct addrinfo hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		err = bctbx_getaddrinfo(addr.c_str(), "5060", &hints, &res);
		if (err != 0) {
			LOGF("Error while processing nat-addresses value '%s': %s", addr.c_str(), gai_strerror(err));
			continue;
		}
		for (ai_it = res; ai_it != nullptr; ai_it = ai_it->ai_next) {
			char ipaddress[NI_MAXHOST] = {0};
			int port = 0;
			if (bctbx_addrinfo_to_ip_address(ai_it, ipaddress, sizeof(ipaddress), &port) == 0) {
				switch (ai_it->ai_family) {
					case AF_INET:
						if (!ipv4_set) {
							natPolicy->setNatV4Address(ipaddress);
							ipv4_set = true;
							SLOGI << "Nat v4 address set: " << ipaddress;
						} else {
							SLOGE << "Ignoring nat-address '" << ipaddress
							      << "', there can be a single one per IP family.";
						}
						break;
					case AF_INET6:
						if (!ipv6_set) {
							natPolicy->setNatV6Address(ipaddress);
							SLOGI << "Nat v6 address set: " << ipaddress;
							ipv6_set = true;
						} else {
							SLOGE << "Ignoring nat-address '" << ipaddress
							      << "', there can be a single one per IP family.";
						}
						break;
					default:
						SLOGE << "Unknown address family while supporting NAT addresses.";
						break;
				}
			}
		}
		bctbx_freeaddrinfo(res);
	}
}

void ConferenceServer::enableSelectedCodecs(const std::list<std::shared_ptr<linphone::PayloadType>>& codecs,
                                            const std::list<std::string>& mimeTypes) {
	for (auto codec : codecs) {
		if (std::find(mimeTypes.begin(), mimeTypes.end(), codec->getMimeType()) != mimeTypes.end()) {
			codec->enable(true);
		} else {
			codec->enable(false);
		}
	}
}

void ConferenceServer::_run() {
	mCore->iterate();
}

std::unique_ptr<AsyncCleanup> ConferenceServer::_stop() {
	const auto sharedThis = shared_from_this();
	mCore->removeListener(sharedThis);
	mRegistrarDb->removeStateListener(sharedThis);
	for (const auto& chatroom : mChatRooms) {
		chatroom->removeListener(sharedThis);
	}
	mSubscriptionHandler.unsubscribeAll();
	return nullptr;
}

void ConferenceServer::loadFactoryUris() {
	const auto* config = mConfigManager->getRoot()->get<GenericStruct>("conference-server");
	const auto* conferenceFactoryUriSetting = config->get<ConfigString>("conference-factory-uri");
	const auto* conferenceFactoryUrisSetting = config->get<ConfigStringList>("conference-factory-uris");
	const auto* conferenceFocusUrisSetting = config->get<ConfigStringList>("conference-focus-uris");
	auto conferenceFactoryUri = conferenceFactoryUriSetting->read();
	auto conferenceFactoryUris = conferenceFactoryUrisSetting->read();
	auto conferenceFocusUris = conferenceFocusUrisSetting->read();

	if (!conferenceFactoryUri.empty()) conferenceFactoryUris.push_back(conferenceFactoryUri);
	if (conferenceFactoryUris.empty()) {
		SLOGI << conferenceFactoryUrisSetting->getCompleteName() << " parameter must be set!";
	}
	auto focus_it = conferenceFocusUris.begin();
	for (auto factoryUri : conferenceFactoryUris) {
		SLOGI << " Trying to match conference factory URI " << factoryUri << " with a conference focus URI";
		if (focus_it != conferenceFocusUris.end()) {
			SLOGI << "Matched conference factory URI " << factoryUri << " with a conference focus URI " << (*focus_it);
			mConfServerUris.push_back({factoryUri, *focus_it++});
		} else {
			LOGF("Number of factory uri [%lu] must match number of focus uri [%lu]", conferenceFactoryUris.size(),
			     conferenceFocusUris.size());
		}
	}
}

void ConferenceServer::onRegistrarDbWritable(bool writable) {
	if (writable) bindAddresses();
}

void ConferenceServer::onChatRoomStateChanged([[maybe_unused]] const shared_ptr<Core>& lc,
                                              const shared_ptr<ChatRoom>& cr,
                                              ChatRoom::State state) {
	if (state == ChatRoom::State::Instantiated) {
		mChatRooms.push_back(cr);
		cr->addListener(shared_from_this());
	} else if (state == ChatRoom::State::Deleted) {
		cr->removeListener(shared_from_this());
		mChatRooms.remove(cr);
	}
}

void ConferenceServer::onConferenceAddressGeneration([[maybe_unused]] const shared_ptr<ChatRoom>& cr) {
	// Not required anymore by the SDK 5.4
	// A faster way of verifying that the id is not taken is to look into the database
}

void ConferenceServer::onParticipantRegistrationSubscriptionRequested(
    const shared_ptr<ChatRoom>& cr, const shared_ptr<const Address>& participantAddr) {
	mSubscriptionHandler.subscribe(cr, participantAddr);
}

void ConferenceServer::onParticipantRegistrationUnsubscriptionRequested(
    const shared_ptr<ChatRoom>& cr, const shared_ptr<const Address>& participantAddr) {
	mSubscriptionHandler.unsubscribe(cr, participantAddr);
}

void ConferenceServer::bindAddresses() {
	if (mAddressesBound) return;

	// Bind the conference factory address in the registrar DB
	bindFactoryUris();

	/* Bind focus URIs */
	bindFocusUris();

	if (mMediaConfig.textEnabled) {
		// Binding loaded chat room
		for (const auto& chatRoom : mCore->getChatRooms()) {
			const auto& peerAddress = chatRoom->getPeerAddress();
			// If the peer address is not one of the focus uris
			if (std::find_if(mConfServerUris.cbegin(), mConfServerUris.cend(), [&peerAddress](const auto& p) {
				    return peerAddress->weakEqual(linphone::Factory::get()->createAddress(p.second));
			    }) == mConfServerUris.cend()) {
				bindChatRoom(peerAddress->asStringUriOnly(), mTransport.str(), nullptr);
			}
		}
	}
	mAddressesBound = true;
}

void ConferenceServer::bindFactoryUris() {
	class FakeListener : public ContactUpdateListener {
		void onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) override {
		}
		void onError(const SipStatus&) override {
		}
		void onInvalid(const SipStatus&) override {
		}
		void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
			SLOGD << "ConferenceServer: ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}
	};
	shared_ptr<FakeListener> listener = make_shared<FakeListener>();

	string uuid = getUuid();
	for (auto conferenceFactoryUri : mConfServerUris) {
		try {
			BindingParameters parameter;
			sip_contact_t* sipContact = sip_contact_create(
			    mHome.home(), reinterpret_cast<const url_string_t*>(url_make(mHome.home(), mTransport.str().c_str())),
			    !uuid.empty() ? su_strdup(mHome.home(), ("+sip.instance=" + UriUtils::grToUniqueId(uuid)).c_str())
			                  : nullptr,
			    nullptr);
			SipUri factory(conferenceFactoryUri.first);

			parameter.callId = "CONFERENCE";
			parameter.path.add(mPath);
			parameter.globalExpire = numeric_limits<int>::max();
			parameter.alias = false;
			parameter.version = 0;
			parameter.withGruu = true;

			// Clear any bindings registered by a conference server in version 2.2. See anchor CNFFACREGKEYMIG
			mRegistrarDb->clear(factory, parameter.callId, listener);

			mRegistrarDb->bind(factory, sipContact, parameter, listener);

		} catch (const sofiasip::InvalidUrlError& e) {
			LOGF("'conference-server' value isn't a SIP URI [%s]", e.getUrl().c_str());
		}
	}
}

void ConferenceServer::bindFocusUris() {
	class FocusListener : public ContactUpdateListener {
	public:
		FocusListener(const shared_ptr<Account>& account, const string& uuid) : mAccount(account), mUuid(uuid) {
		}
		void onRecordFound(const shared_ptr<Record>& r) override {
			if (r->getExtendedContacts().empty()) {
				LOGF("Focus address bind failed.");
				return;
			}
			shared_ptr<ExtendedContact> ec = r->extractContactByUniqueId(UriUtils::grToUniqueId(mUuid));
			if (!ec) {
				throw FlexisipException{"focus uri was not recorded in registrar database"};
			}
			url_t* pub_gruu = r->getPubGruu(ec, mHome.home());
			if (!pub_gruu) {
				throw FlexisipException{"focus binding does not have public gruu"};
			}
			shared_ptr<linphone::Address> gruuAddr =
			    linphone::Factory::get()->createAddress(url_as_string(mHome.home(), pub_gruu));
			SLOGI << "Focus address [" << gruuAddr->asStringUriOnly() << "] is bound";
			mAccount->setContactAddress(gruuAddr);
		}
		void onError(const SipStatus&) override {
		}
		void onInvalid(const SipStatus&) override {
		}
		void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
			SLOGD << "ConferenceServer: ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}

	private:
		shared_ptr<Account> mAccount;
		const string mUuid;
	};
	string uuid = getUuid();

	for (auto account : mCore->getAccountList()) {
		BindingParameters parameter;
		auto identityAddress = account->getParams()->getIdentityAddress();
		auto factoryAddress = Factory::get()->createAddress(account->getParams()->getConferenceFactoryUri());

		if (identityAddress->equal(factoryAddress)) continue;

		sip_contact_t* sipContact = sip_contact_create(
		    mHome.home(), reinterpret_cast<const url_string_t*>(url_make(mHome.home(), mTransport.str().c_str())),
		    !uuid.empty() ? su_strdup(mHome.home(), ("+sip.instance=" + UriUtils::grToUniqueId(uuid)).c_str())
		                  : nullptr,
		    nullptr);

		parameter.callId = "CONFERENCE";
		parameter.path.add(mPath);
		parameter.globalExpire = numeric_limits<int>::max();
		parameter.alias = false;
		parameter.version = 0;
		parameter.withGruu = true;

		SipUri focus(account->getParams()->getIdentityAddress()->asStringUriOnly());
		shared_ptr<FocusListener> listener = make_shared<FocusListener>(account, uuid);
		mRegistrarDb->bind(focus, sipContact, parameter, listener);
	}
}

void ConferenceServer::bindChatRoom(const string& bindingUrl,
                                    const string& contact,
                                    const shared_ptr<ContactUpdateListener>& listener) {
	BindingParameters parameter;
	const auto gruu = getUuid();

	sip_contact_t* sipContact =
	    sip_contact_create(mHome.home(), reinterpret_cast<const url_string_t*>(url_make(mHome.home(), contact.c_str())),
	                       su_strdup(mHome.home(), ("+sip.instance=" + UriUtils::grToUniqueId(gruu)).c_str()), nullptr);

	parameter.callId = "dummy-call-id"; // Mandatory parameter but useless in our case.
	parameter.path.add(mPath);
	parameter.globalExpire = numeric_limits<int>::max();
	parameter.alias = false;
	parameter.version = 0;
	parameter.withGruu = true;

	SipUri uri(bindingUrl);

	if (uri.getUser().empty()) throw FlexisipException{"trying to bind with no username"};

	mRegistrarDb->bind(uri, sipContact, parameter, listener);
}

namespace {
// Statically define default configuration items
auto& defineConfig = ConfigManager::defaultInit().emplace_back([](GenericStruct& root) {
	ConfigItemDescriptor items[] = {
	    {
	        Boolean,
	        "enabled",
	        "Enable conference server", /* Do we need this ? The systemd enablement should be sufficient. */
	        "true",
	    },
	    {
	        String,
	        "transport",
	        "Unique SIP URI on which the server is listening.",
	        "sip:127.0.0.1:6064;transport=tcp",
	    },
	    {
	        StringList,
	        "conference-factory-uris",
	        "List of SIP URIs used by clients to create conferences. This implicitly defines the list of SIP domains "
	        "managed by the conference server. Example:\n"
	        "sip:conference-factory@sip.linphone.org sip:conference-factory@sip.linhome.org",
	        "",
	    },
	    {
	        StringList,
	        "conference-focus-uris",
	        "List of template focus URIs to use when conferences are created through the conference factory.\n"
	        "Focus URIs are unique SIP URIs targeting a specific conference. A 'conf-id' URI parameter providing "
	        "uniqueness is automatically appended at runtime. Example, setting:\n"
	        "conference-focus-uris=sip:conference-focus@sip.linphone.org\n"
	        "instructs the server to generate conference URIs in the form of "
	        "'sip:conference-focus@sip.linphone.org;conf-id=<random string>'\n"
	        "when a client requests to create a conference.",
	        "",
	    },
	    {
	        String,
	        "outbound-proxy",
	        "The SIP proxy URI to which the server will send all outgoing requests.",
	        "sip:127.0.0.1:5060;transport=tcp",
	    },
	    {
	        StringList,
	        "local-domains",
	        "Domains managed by the local SIP service, i.e. domains for which user registration information "
	        "can be found directly in the local registrar database (Redis database).\n"
	        "For external domains (not in this list), a 'reg' SUBSCRIBE (RFC3680) will be emitted. "
	        "It is not necessary to list domains that appear in the 'conference-factory-uris' property. "
	        "They are assumed to be local domains already.\n"
	        "Example: sip.linphone.org conf.linphone.org linhome.org",
	        "",
	    },
	    {
	        IntegerRange,
	        "audio-port",
	        "Audio port to use for RTP and RTCP traffic. You can set a specific port, a range of ports or let the "
	        "server ask the kernel for an available port (special value: 0).\n"
	        "Examples: 'audio-port=0' or 'audio-port=12345' or 'audio-port=1024-65535'",
	        "0",
	    },
	    {
	        IntegerRange,
	        "video-port",
	        "Video port to use for RTP and RTCP traffic. You can set a specific port, a range of ports or let the "
	        "server ask the kernel for an available port (special value: 0).\n"
	        "Examples: 'video-port=0' or 'video-port=12345' or 'video-port=1024-65535'",
	        "0",
	    },
	    {
	        String,
	        "database-backend",
	        "Type of database the server will use to store chat room and conference data. Provided that the required "
	        "Soci modules are installed, the supported databases are: `mysql`, `sqlite3`",
	        "mysql",
	    },
	    {
	        String,
	        "database-connection-string",
	        "Configuration parameters of the database to store chat room and conference data.\n"
	        "The basic format is \"key=value key2=value2\"."
	        "For MySQL, the following is a valid configuration: db='mydb' user='myuser' password='mypass' "
	        "host='myhost.com'.\n"
	        "Please refer to the Soci documentation of your selected backend:\n"
	        "https://soci.sourceforge.net/doc/release/3.2/backends/mysql.html\n"
	        "https://soci.sourceforge.net/doc/release/3.2/backends/sqlite3.html",
	        "db='mydb' user='myuser' password='mypass' host='myhost.com'",
	    },
	    {
	        Boolean,
	        "check-capabilities",
	        "True to make the server check device capabilities before inviting them to a session.\n"
	        "The capability check is currently limited to Linphone clients that put a '+org.linphone.specs' contact "
	        "parameter. This parameter indicates whether they support group chat and secured group chat or not.",
	        "true",
	    },
	    {
	        StringList,
	        "supported-media-types",
	        "List of media types supported by the server.\n"
	        "This allows to specify if this instance is able to provide chat services or audio/video conference "
	        "services, or both.\n"
	        "Valid values: audio, video, text.\n"
	        "Example: audio video text",
	        "text",
	    },
	    {
	        String,
	        "media-engine-type",
	        "Type of media engine to use.\n"
	        "In mixer mode, the server will mix audio streams and handle any necessary modification to the streams "
	        "before sending data.\n"
	        "In SFU mode, all streams are simply forwarded to destinations without any modification. This is the mode "
	        "required for end to end encryption.\n"
	        "Valid values: mixer, sfu.",
	        "mixer",
	    },
	    {
	        String,
	        "encryption",
	        "Type of media encryption the server will offer when calling participants to an audio or video "
	        "conference.\n"
	        "Valid values: none, sdes, zrtp, dtls.",
	        "none",
	    },
	    {
	        StringList,
	        "nat-addresses",
	        "Public host name or IP addresses of the server.\n"
	        "Setting this parameter is required when the conference server is deployed behind a firewall. This way, "
	        "public IP address (v4, v6) can be advertised in SDP, as ICE server-reflexive candidates in order for the "
	        "server to receive RTP media packets from clients.\n"
	        "If no hostname is given, the v4 and v6 IP addresses can be listed, in any order. It is not possible to "
	        "configure several v4 addresses or several v6 addresses.\n"
	        "Example:\n"
	        "nat-addresses=conference.linphone.org\n"
	        "nat-addresses=5.135.31.160   2001:41d0:303:3aee::1",
	        "",
	    },
	    {
	        Boolean,
	        "empty-chat-room-deletion",
	        "Server shall delete chat rooms that have no registered participants.",
	        "true",
	    },
	    {
	        String,
	        "state-directory",
	        "Directory where the server state files are stored.\n",
	        DEFAULT_LIB_DIR,
	    },
	    {
	        DurationS,
	        "call-timeout",
	        "Server will kill all incoming calls that last longer than the defined value.\n"
	        "Special value 0 disables this feature.",
	        "0",
	    },

	    // Deprecated parameters:
	    {
	        String,
	        "conference-factory-uri",
	        "uri where the client must ask to create a conference. For example:\n"
	        "conference-factory-uri=sip:conference-factory@sip.linphone.org",
	        "",
	    },
	    {
	        Boolean,
	        "enable-one-to-one-chat-room",
	        "Whether one-to-one chat room creation is allowed or not.",
	        "true",
	    },
	    config_item_end,
	};

	auto uS = make_unique<GenericStruct>(
	    "conference-server",
	    "Flexisip conference server parameters.\n"
	    "The Flexisip conference server manages group chat and audio/video conferences.\n"
	    "It follows the concepts of RFC4579 for conference establishment and management. Factory and focus URIs must "
	    "be configured.\n"
	    "The server requires a MariaDB/MySQL database in order to store chatroom or conference states (participants "
	    "and their devices).\n"
	    "For chatting capabilities, the server requires a Registrar backend (see section module::Registrar) to "
	    "discover devices (or client instances) of each participant. This requirement creates an explicit dependency "
	    "on the Flexisip proxy server. Please note that this dependency is not required for audio/video conferences.",
	    0);
	auto* s = root.addChild(std::move(uS));
	s->addChildrenValues(items);
	s->get<ConfigString>("conference-factory-uri")
	    ->setDeprecated("2020-09-30", "2.1.0",
	                    "Use 'conference-factory-uris' instead, that allows to declare multiple factory uris.");
	s->get<ConfigBoolean>("enable-one-to-one-chat-room")
	    ->setDeprecated("2022-09-21", "2.2.0", "This parameter will be forced to 'true' in further versions.");
});
} // namespace

filesystem::path ConferenceServer::getStateDir(const std::string& subdir) const {
	return filesystem::path{mStateDir}.append(subdir);
}

void ConferenceServer::ensureDirectoryCreated(const filesystem::path& directory) {
	struct stat st;
	if (stat(directory.c_str(), &st) != 0 && errno == ENOENT) {
		SLOGD << "Creating flexisip's state directory: " << directory;
		string command("mkdir -p");
		command += " \"" + directory.string() + "\"";
		int status = system(command.c_str());
		if (status == -1 || WEXITSTATUS(status) != 0) {
			LOGF("Directory %s doesn't exist and could not be created (insufficient permissions ?). Please create it "
			     "manually.",
			     directory.c_str());
		}
	}
}

filesystem::path ConferenceServer::getUuidFilePath() const {
	return getStateDir().append(sUuidFile);
}

const string& ConferenceServer::readUuid() {
	ifstream fi;
	mUuid = "";
	filesystem::path path = getUuidFilePath();
	fi.open(path);
	if (!fi.is_open()) {
		SLOGD << "Cannot open uuid file " << path << ": " << strerror(errno);
		return mUuid;
	}
	fi >> mUuid;
	fi.close();
	SLOGD << "Using uuid '" << mUuid << "'";
	return mUuid;
}

void ConferenceServer::writeUuid(const string& uuid) {
	ofstream fo;
	filesystem::path stateDir = getStateDir();

	ensureDirectoryCreated(stateDir);

	mUuid = uuid;
	filesystem::path path = getUuidFilePath();
	fo.open(path);
	if (!fo.is_open()) {
		SLOGE << "Cannot open uuid file " << path << ": " << strerror(errno);
		return;
	}
	fo << uuid;
	fo.close();
}

std::string ConferenceServer::getUuid() {
	if (mUuid.empty()) mUuid = mCore->getConfig()->getString("misc", "uuid", "");
	return mUuid;
}

} // namespace flexisip
