/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <chrono>
#include <fstream>

#include "belle-sip/utils.h"
#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/flexisip-version.h"
#include "registrar/binding-parameters.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registration-events/client.hh"
#include "sofia-sip/sip_header.h"
#include "utils/configuration/media.hh"
#include "utils/configuration/transport.hh"
#include "utils/string-utils.hh"
#include "utils/uri-utils.hh"

using namespace std;
using namespace std::chrono;
using namespace linphone;

namespace flexisip {

sofiasip::Home ConferenceServer::mHome;

void ConferenceServer::_init() {
	const auto* config = mConfigManager->getRoot()->get<GenericStruct>("conference-server");

	// Transport configuration.
	const auto transports = Factory::get()->createTransports();
	const auto* transportParam = config->get<ConfigString>("transport");
	if (transportParam->read().empty()) throw BadConfigurationEmpty{transportParam};
	configuration_utils::configureTransport(transports, transportParam, {"", "udp", "tcp"});
	mTransport = SipUri{transportParam->read()};
	const auto bindAddress = mTransport.getHost();

	mCheckCapabilities = config->get<ConfigBoolean>("check-capabilities")->read();
	mStateDir = config->get<ConfigString>("state-directory")->read();

	// Read enabled media types (audio, video, text).
	const auto* mediaTypesParam = config->get<ConfigStringList>("supported-media-types");
	auto mediaTypes = mediaTypesParam->read();
	if (find(mediaTypes.begin(), mediaTypes.end(), "audio") != mediaTypes.end()) mMediaConfig.audioEnabled = true;
	if (find(mediaTypes.begin(), mediaTypes.end(), "video") != mediaTypes.end()) mMediaConfig.videoEnabled = true;
	if (find(mediaTypes.begin(), mediaTypes.end(), "text") != mediaTypes.end()) mMediaConfig.textEnabled = true;
	if (mMediaConfig.audioEnabled == false && mMediaConfig.videoEnabled == false && mMediaConfig.textEnabled == false)
		throw BadConfigurationWithHelp{
		    mediaTypesParam, "no media types enabled in conference server (at least one media type must be enabled)"};

	// Linphone-sdk configuration.
	auto configLinphone = Factory::get()->createConfig("");
	configLinphone->setString("sip", "bind_address", bindAddress);
	configLinphone->setBool("misc", "conference_server_enabled", true);
	configLinphone->setBool("misc", "enable_one_to_one_chat_room",
	                        config->get<ConfigBoolean>("enable-one-to-one-chat-room")->read());
	configLinphone->setBool("misc", "empty_chat_room_deletion",
	                        config->get<ConfigBoolean>("empty-chat-room-deletion")->read());

	if (mMediaConfig.textEnabled) {
		const auto* dbConnectionStringParam = config->get<ConfigString>("database-connection-string");
		string dbUri = dbConnectionStringParam->read();
		if (dbUri.empty())
			throw BadConfigurationWithHelp{
			    dbConnectionStringParam,
			    dbConnectionStringParam->getCompleteName() +
			        " is not set but is mandatory when 'text' media type is enabled",
			};
		configLinphone->setInt("misc", "hide_empty_chat_rooms", 0);
		configLinphone->setInt("misc", "hide_chat_rooms_from_removed_proxies", 0);
		configLinphone->setString("storage", "backend", config->get<ConfigString>("database-backend")->read());
		configLinphone->setString("storage", "uri", dbUri);
		configLinphone->setBool("misc", "keep_gruu_in_conference_address", true);
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
	// To make sure contact address is not fixed by belle-sip.
	configLinphone->setBool("net", "enable_nat_helper", false);

	configuration_utils::configureMediaEngineMode(configLinphone, configuration_utils::MediaEngine::AUDIO,
	                                              config->get<ConfigString>("audio-engine-mode"));
	configuration_utils::configureMediaEngineMode(configLinphone, configuration_utils::MediaEngine::VIDEO,
	                                              config->get<ConfigString>("video-engine-mode"));

	string uuid = readUuid();
	if (!uuid.empty()) configLinphone->setString("misc", "uuid", uuid);

	// Prevent the default log handler from being reset while LinphoneCore construction.
	configLinphone->setBool("logging", "disable_stdout", true);

	mCore = Factory::get()->createCoreWithConfig(configLinphone, nullptr);

	mCore->setInCallTimeout(config->get<ConfigDuration<chrono::seconds>>("call-timeout")->readAndCast().count());
	mCore->enableRtpBundle(true);
	mCore->enableEchoCancellation(false);

	const auto* noRTPTimeoutParameter = config->get<ConfigDuration<chrono::seconds>>("no-rtp-timeout");
	const auto noRTPTimeout = noRTPTimeoutParameter->read();
	if (noRTPTimeout <= 0ms) throw BadConfigurationValue{noRTPTimeoutParameter, "duration must be strictly positive"};

	mCore->setNortpTimeout(static_cast<int>(chrono::duration_cast<chrono::seconds>(noRTPTimeout).count()));

	mCore->setUserAgent("Flexisip-conference", FLEXISIP_GIT_VERSION);
	mCore->addListener(shared_from_this());
	mCore->enableConferenceServer(true);
	mCore->setTransports(transports);

	// Make LinphoneCore slice incoming LIME multipart messages so every forwarded message contains only one encrypted
	// message instead of having the encrypted version for each recipient.
	mCore->enableLimeX3Dh(true);

	const int audioPortMin = config->get<ConfigIntRange>("audio-port")->readMin();
	const int audioPortMax = config->get<ConfigIntRange>("audio-port")->readMax();
	configuration_utils::setMediaPort(audioPortMin, audioPortMax, *mCore, &Core::setAudioPort,
	                                  &Core::setAudioPortRange);

	const int videoPortMin = config->get<ConfigIntRange>("video-port")->readMin();
	const int videoPortMax = config->get<ConfigIntRange>("video-port")->readMax();
	configuration_utils::setMediaPort(videoPortMin, videoPortMax, *mCore, &Core::setVideoPort,
	                                  &Core::setVideoPortRange);

	mCore->setUseFiles(true); // No sound card shall be used in calls.

	// Let the conference server work with all liblinphone's default audio codecs (opus, speex, pcmu, pcma)
	// enableSelectedCodecs(mCore->getAudioPayloadTypes(), {"opus", "speex"});

	// We have to restrict for video because as of today only VP8 is supported.
	enableSelectedCodecs(mCore->getVideoPayloadTypes(), {"VP8"});

	const auto encryption = config->get<ConfigString>("encryption")->read();
	const auto encryptionMode = StringUtils::string2MediaEncryption(encryption);
	if (encryptionMode) {
		mCore->setMediaEncryption(*encryptionMode);
	}

	// Create a directory in order to automatically generate DTLS-SRTP certificates.
	const auto dtlsDir = getStateDir("dtls-srtp");
	ensureDirectoryCreated(dtlsDir);
	mCore->setUserCertificatesPath(dtlsDir);

	mCore->setVideoDisplayFilter("MSExtDisplay");

	// Enable ICE (with host candidates only) so that the relay service of the proxies is bypassed.
	shared_ptr<NatPolicy> natPolicy = mCore->createNatPolicy();
	natPolicy->enableIce(true);
	configuration_utils::configureNatAddresses(natPolicy, config->get<ConfigStringList>("nat-addresses"));
	mCore->setNatPolicy(natPolicy);

	loadFactoryUris();

	const auto* outboundProxyParam = config->get<ConfigString>("outbound-proxy");
	auto outboundProxy = outboundProxyParam->read();
	auto outboundProxyAddress = Factory::get()->createAddress(outboundProxy);
	if (!outboundProxyAddress) throw BadConfigurationValue{outboundProxyParam};

	bool defaultAccountSet = false;
	for (const auto& conferenceServerUris : mConfServerUris) {
		const auto factoryUri = Factory::get()->createAddress(conferenceServerUris.first);
		const auto accountParams = mCore->createAccountParams();

		if (!conferenceServerUris.second.empty()) {
			auto focusUri = Factory::get()->createAddress(conferenceServerUris.second);
			accountParams->setIdentityAddress(focusUri);
		} else {
			accountParams->setIdentityAddress(factoryUri);
		}

		accountParams->setServerAddress(outboundProxyAddress);
		accountParams->enableRegister(false);
		accountParams->enableOutboundProxy(true);
		accountParams->setConferenceFactoryAddress(factoryUri);
		auto account = mCore->createAccount(accountParams);

		// The default contact address is the identity address.
		// It will be used if the connection to the REDIS server is broken or the answer is very slow and a client calls
		// a conference before onRecordFound() is executed.
		account->setContactAddress(accountParams->getIdentityAddress());
		mCore->addAccount(account);
		if (!defaultAccountSet) {
			defaultAccountSet = true;
			mCore->setDefaultAccount(account);
		}
		mLocalDomains.push_back(factoryUri->getDomain());
	}

	// Get additional local domains.
	auto otherLocalDomains = config->get<ConfigStringList>("local-domains")->read();
	for (auto& domain : otherLocalDomains)
		mLocalDomains.emplace_back(std::move(domain));

	otherLocalDomains.clear();
	mLocalDomains.sort();
	mLocalDomains.unique();

	auto refreshDelay = config->get<ConfigDuration<seconds>>("subscription-refresh-delay")->readAndCast();
	mRegEventClientFactory = make_shared<RegistrationEvent::ClientFactory>(mCore, refreshDelay);

	mCore->enableEmptyChatroomsDeletion(config->get<ConfigBoolean>("empty-chat-room-deletion")->read());
	if (config->get<ConfigBoolean>("cleanup-expired-conferences")->read())
		// Hardcoded cleanup period of 1 hour
		mCore->setConferenceCleanupPeriod(600);

	mCore->setConferenceAvailabilityBeforeStart(
	    config->get<ConfigDuration<seconds>>("conferences-availability-before-start")->readAndCast().count());

	mCore->setConferenceExpirePeriod(
	    config->get<ConfigDuration<seconds>>("conferences-expiry-time")->readAndCast().count());

	Status err = mCore->start();
	if (err == -2) throw ExitFailure{"the Linphone core could not start because the connection to the database failed"};
	if (err < 0) throw ExitFailure{"the Linphone core failed to start (please check the logs)"};

	// In case no uuid was set in persistent state directory, take the one randomly chosen by Liblinphone.
	if (uuid.empty()) writeUuid(configLinphone->getString("misc", "uuid", ""));
	else if (configLinphone->getString("misc", "uuid", "") != uuid) throw BadConfiguration{"inconsistent uuid"};

	mRegistrarDb->addStateListener(shared_from_this());
	if (mRegistrarDb->isWritable()) bindAddresses();
}

void ConferenceServer::enableSelectedCodecs(const list<shared_ptr<linphone::PayloadType>>& codecs,
                                            const list<string>& mimeTypes) {
	for (const auto& codec : codecs) {
		if (find(mimeTypes.begin(), mimeTypes.end(), codec->getMimeType()) != mimeTypes.end()) {
			codec->enable(true);
		} else {
			codec->enable(false);
		}
	}
}

void ConferenceServer::_run() {
	mCore->iterate();
}

unique_ptr<AsyncCleanup> ConferenceServer::_stop() {
	const auto sharedThis = shared_from_this();
	mCore->removeListener(sharedThis);
	mRegistrarDb->removeStateListener(sharedThis);
	for (const auto& chatroom : mChatRooms) {
		chatroom->removeListener(sharedThis);
	}
	mSubscriptionHandler.unsubscribeAll();
	mCore->stop();
	return nullptr;
}

void ConferenceServer::loadFactoryUris() {
	const auto* config = mConfigManager->getRoot()->get<GenericStruct>("conference-server");
	const auto* conferenceFactoryUrisSetting = config->get<ConfigStringList>("conference-factory-uris");
	const auto* conferenceFocusUrisSetting = config->get<ConfigStringList>("conference-focus-uris");
	auto conferenceFactoryUris = conferenceFactoryUrisSetting->read();
	auto conferenceFocusUris = conferenceFocusUrisSetting->read();

	if (conferenceFactoryUris.empty()) {
		LOGI << conferenceFactoryUrisSetting->getCompleteName() << " parameter must be set!";
	}
	auto focus_it = conferenceFocusUris.begin();
	for (const auto& factoryUri : conferenceFactoryUris) {
		LOGI << "Trying to match conference factory URI " << factoryUri << " with a conference focus URI";
		if (focus_it != conferenceFocusUris.end()) {
			LOGI << "Matched conference factory URI " << factoryUri << " with a conference focus URI " << (*focus_it);
			mConfServerUris.emplace_back(factoryUri, *focus_it++);
		} else {
			throw BadConfiguration{"number of factory SIP URIs (" + to_string(conferenceFactoryUris.size()) +
			                       ") must match the number of focus SIP URIs (" +
			                       to_string(conferenceFocusUris.size()) + ")"};
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

void ConferenceServer::onConferenceAddressGeneration(const shared_ptr<ChatRoom>&) {
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
			if (find_if(mConfServerUris.cbegin(), mConfServerUris.cend(), [&peerAddress](const auto& p) {
				    return peerAddress->weakEqual(Factory::get()->createAddress(p.second));
			    }) == mConfServerUris.cend()) {
				bindChatRoom(peerAddress->asStringUriOnly(), mTransport.str(), nullptr);
			}
		}
	}
	mAddressesBound = true;
}

void ConferenceServer::bindFactoryUris() {
	class FakeListener : public ContactUpdateListener {
		void onRecordFound([[maybe_unused]] const shared_ptr<Record>& r) override {}
		void onError(const SipStatus&) override {}
		void onInvalid(const SipStatus&) override {}
		void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
			LOGD << "ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}
	};
	shared_ptr<FakeListener> listener = make_shared<FakeListener>();

	string uuid = getUuid();
	for (const auto& conferenceFactoryUri : mConfServerUris) {
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
			parameter.globalExpire = chrono::seconds{numeric_limits<int>::max()};
			parameter.alias = false;
			parameter.version = 0;
			parameter.withGruu = true;

			// Clear any bindings registered by a conference server in version 2.2. See anchor CNFFACREGKEYMIG
			mRegistrarDb->clear(factory, parameter.callId, listener);

			mRegistrarDb->bind(factory, sipContact, parameter, listener);

		} catch (const sofiasip::InvalidUrlError& e) {
			throw BadConfiguration{"invalid conference-server SIP URI '" + e.getUrl() + "'"};
		}
	}
}

void ConferenceServer::bindFocusUris() {
	class FocusListener : public ContactUpdateListener {
	public:
		FocusListener(const shared_ptr<Account>& account, const string& uuid) : mAccount(account), mUuid(uuid) {}
		void onRecordFound(const shared_ptr<Record>& r) override {
			if (r->getExtendedContacts().empty()) throw FlexisipException{"focus address bind failed"};

			shared_ptr<ExtendedContact> ec = r->extractContactByUniqueId(UriUtils::grToUniqueId(mUuid));
			if (!ec) throw FlexisipException{"focus uri was not recorded in registrar database"};

			url_t* pub_gruu = r->getPubGruu(ec, mHome.home());
			if (!pub_gruu) throw FlexisipException{"focus binding does not have public gruu"};

			shared_ptr<Address> gruuAddr = Factory::get()->createAddress(url_as_string(mHome.home(), pub_gruu));
			LOGI << "Focus address [" << gruuAddr->asStringUriOnly() << "] is bound";
			mAccount->setContactAddress(gruuAddr);
		}
		void onError(const SipStatus&) override {}
		void onInvalid(const SipStatus&) override {}
		void onContactUpdated(const shared_ptr<ExtendedContact>& ec) override {
			LOGD << "ExtendedContact contactId=" << ec->contactId() << " callId=" << ec->callId();
		}

	private:
		shared_ptr<Account> mAccount;
		const string mUuid;
	};
	string uuid = getUuid();

	for (const auto& account : mCore->getAccountList()) {
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
		parameter.globalExpire = chrono::seconds{numeric_limits<int>::max()};
		parameter.alias = false;
		parameter.version = 0;
		parameter.withGruu = true;

		SipUri focus(account->getParams()->getIdentityAddress()->asStringUriOnly());
		auto listener = make_shared<FocusListener>(account, uuid);
		mRegistrarDb->bind(focus, sipContact, parameter, listener);
	}
}

void ConferenceServer::bindChatRoom(const string& bindingUrl,
                                    const string& contact,
                                    const shared_ptr<ContactUpdateListener>& listener) {
	SipUri uri(bindingUrl);
	auto gruu = uri.getParam("gr");
	if (gruu.empty()) gruu = getUuid();

	sip_contact_t* sipContact =
	    sip_contact_create(mHome.home(), reinterpret_cast<const url_string_t*>(url_make(mHome.home(), contact.c_str())),
	                       su_strdup(mHome.home(), ("+sip.instance=" + UriUtils::grToUniqueId(gruu)).c_str()), nullptr);

	BindingParameters parameter;
	parameter.callId = "dummy-call-id"; // Mandatory parameter but useless in our case.
	parameter.path.add(mPath);
	parameter.globalExpire = chrono::seconds{numeric_limits<int>::max()};
	parameter.alias = false;
	parameter.version = 0;
	parameter.withGruu = true;

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
	        "This parameter cannot be empty.\n"
	        "If 'text' media type is enabled, 'database-connection-string' must be set.\n"
	        "Valid values: 'audio', 'video', 'text'.\n"
	        "Example: audio video text",
	        "text",
	    },
	    {
	        String,
	        "audio-engine-mode",
	        "Valid values: 'mixer', 'semi-sfu', 'sfu'\n"
	        "- 'mixer': The server mixes all relevant streams before sending the final computed stream to "
	        "participants. This mode is quite compute-intensive because it involves several decoding/encoding "
	        "operations.\n"
	        "- 'semi-sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations. However, RTP headers are re-written by the server.\n"
	        "- 'sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations and with only slight modifications made to RTP headers. This is the mode required for "
	        "end-to-end encryption.\n",
	        "mixer",
	    },
	    {
	        String,
	        "video-engine-mode",
	        "Valid values: 'semi-sfu', 'sfu'\n"
	        "- 'semi-sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations. However, RTP headers are re-written by the server.\n"
	        "- 'sfu': The server only forwards relevant streams to participants without any decoding/encoding "
	        "operations and with only slight modifications made to RTP headers. This is the mode required for "
	        "end-to-end encryption.\n",
	        "semi-sfu",
	    },
	    {
	        String,
	        "encryption",
	        "Type of media encryption the server will offer when calling participants to an audio or video "
	        "conference.\n"
	        "Valid values: none, sdes, zrtp, dtls-srtp.",
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
	        "Examples:\n"
	        "nat-addresses=conference.linphone.org\n"
	        "nat-addresses=5.135.31.160  2001:41d0:303:3aee::1",
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
	        "subscription-refresh-delay",
	        "Delay before refreshing external subscriptions to the regevent-server.\n"
	        "It is not recommended to reduce this parameter below 1 minute as refreshing all subscriptions generates "
	        "a significant traffic.",
	        "10min",
	    },
	    {
	        DurationS,
	        "call-timeout",
	        "Server will kill all incoming calls that last longer than the defined value.\n"
	        "Special value 0 disables this feature.",
	        "0",
	    },
	    {
	        DurationS,
	        "no-rtp-timeout",
	        "Duration after which the server will terminate a call if no RTP packets are received from the other call "
	        "participant. For performance reasons, this parameter cannot be disabled.",
	        "30",
	    },
	    {
	        Boolean,
	        "cleanup-expired-conferences",
	        "If enabled, the conference server will periodically remove all expired conferences.",
	        "true",
	    },
	    {
	        DurationS,
	        "conferences-availability-before-start",
	        "Duration used to set how long before the start time of a conference it is possible to join it.",
	        "100y",
	    },
	    {
	        DurationS,
	        "conferences-expiry-time",
	        "Duration after the end of the conference for which it is still possible to join it.\n"
	        "The end of a conference, here, is the latest time between the scheduled end time, and the time when the "
	        "last participant has left.",
	        "30d",
	    },

	    // Deprecated parameters:
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
	s->get<ConfigBoolean>("enable-one-to-one-chat-room")
	    ->setDeprecated("2022-09-21", "2.2.0", "This parameter will be forced to 'true' in further versions.");
});
} // namespace

filesystem::path ConferenceServer::getStateDir(const string& subdir) const {
	return filesystem::path{mStateDir}.append(subdir);
}

void ConferenceServer::ensureDirectoryCreated(const filesystem::path& directory) {
	struct stat st;
	if (stat(directory.c_str(), &st) != 0 && errno == ENOENT) {
		LOGD << "Creating Flexisip state directory: " << directory;
		string command("mkdir -p");
		command += " \"" + directory.string() + "\"";
		int status = system(command.c_str());
		if (status == -1 || WEXITSTATUS(status) != 0) {
			throw FlexisipException{
			    "directory '" + directory.string() +
			    "' does not exist and could not be created (insufficient permissions?), please create it manually"};
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
		LOGD << "Cannot open uuid file " << path << ": " << strerror(errno);
		return mUuid;
	}
	fi >> mUuid;
	fi.close();
	LOGD << "Using uuid '" << mUuid << "'";
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
		LOGE << "Cannot open uuid file " << path << ": " << strerror(errno);
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