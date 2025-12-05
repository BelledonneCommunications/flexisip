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

#pragma once

#include <ifaddrs.h>

#include <filesystem>
#include <memory>
#include <string>

#if defined(HAVE_CONFIG_H) && !defined(FLEXISIP_INCLUDED)
#include "flexisip-config.h"
#define FLEXISIP_INCLUDED
#endif

#if ENABLE_MDNS
#include "belle-sip/belle-sip.h"
#endif

#include "sofia-sip/nta.h"
#include "sofia-sip/nth.h"
#include "sofia-sip/sip.h"

#include "agent-interface.hh"
#include "auth/db/authdb.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"
#include "i-supervisor-notifier.hh"
#include "registrar/registrar-db.hh"
#include "transaction/incoming-agent.hh"
#include "transaction/outgoing-agent.hh"
#include "transport.hh"

namespace flexisip {

class Module;
class NatTraversalStrategy;
class DomainRegistrationManager;

/**
 * Represents a SIP agent which is in charge of receiving requests (through configured SIP transports), injecting them
 * into the module chain and sending requests to destinations.
 **/
class Agent : public AgentInterface,
              public IncomingAgent,
              public OutgoingAgent,
              public ConfigValueListener,
              public std::enable_shared_from_this<Agent> {
	friend class IncomingTransaction;
	friend class OutgoingTransaction;
	friend class Module;

public:
	static constexpr std::string_view mLogPrefix{"Agent"};

	Agent(const std::shared_ptr<sofiasip::SuRoot>& root,
	      const std::shared_ptr<ConfigManager>& cm,
	      const std::shared_ptr<AuthDb>& authDb,
	      const std::shared_ptr<RegistrarDb>& registrarDb);

	~Agent() override;

	/**
	 * Add agent and modules sections.
	 */
	static void addConfigSections(ConfigManager& cfg);
	/**
	 * Load plugins and add their sections.
	 */
	static void addPluginsConfigSections(ConfigManager& cfg);

	void applyProxyToProxyTransportSettings(tport_t* tp);
	bool doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) override;
	void unloadConfig();

	void start(const std::string& transport_override, const std::string& passphrase);
	void idle();

	void injectRequest(std::unique_ptr<RequestSipEvent>&& ev) override;
	std::unique_ptr<ResponseSipEvent> injectResponse(std::unique_ptr<ResponseSipEvent>&& ev) override;
	void processRequest(std::unique_ptr<RequestSipEvent>&& ev);
	std::unique_ptr<ResponseSipEvent> processResponse(std::unique_ptr<ResponseSipEvent>&& ev) override;

	void incrReplyStat(int status);
	void sendTrap(const GenericEntry* source, const std::string& msg) const;

	bool isUs(const char* host, const char* port, bool check_aliases) const;
	bool isUs(const url_t* url, bool check_aliases = true) const;
	int countUsInVia(sip_via_t* via) const;
	url_t* urlFromTportName(su_home_t* home, const tp_name_t* name);

	/**
	 * @return the module associated with the role (throws an exception if no module is found).
	 */
	std::shared_ptr<Module> findModuleByRole(const std::string& moduleRole) const;

	EventLogWriter* getEventLogWriter() const {
		return mLogWriter.get();
	}
	void setEventLogWriter(std::unique_ptr<EventLogWriter>&& value) {
		mLogWriter = std::move(value);
	}

	std::shared_ptr<Http2Client> getFlexiApiClient() const noexcept override {
		return mFlexiApiClient;
	}
	void setFlexiApiClient(const std::shared_ptr<Http2Client>& flexiApiClient) noexcept {
		mFlexiApiClient = flexiApiClient;
	}

	const std::shared_ptr<sofiasip::SuRoot>& getRoot() const noexcept override {
		return mRoot;
	}
	const ConfigManager& getConfigManager() const {
		return *mConfigManager;
	}
	AuthDb& getAuthDb() {
		return *mAuthDb;
	}
	RegistrarDb& getRegistrarDb() {
		return *mRegistrarDb;
	}
	nta_agent_t* getSofiaAgent() const override {
		return mAgent;
	}
	std::weak_ptr<Agent> getAgent() noexcept override {
		return weak_from_this();
	}
	std::shared_ptr<OutgoingAgent> getOutgoingAgent() override {
		return shared_from_this();
	}
	std::shared_ptr<IncomingAgent> getIncomingAgent() override {
		return shared_from_this();
	}
	nth_engine_t* getHttpEngine() {
		return mHttpEngine;
	}
	DomainRegistrationManager* getDRM() {
		return mDrm;
	}
	const std::shared_ptr<NatTraversalStrategy>& getNatTraversalStrategy() const {
		return mNatTraversalStrategy;
	}
	const char* getServerString() const {
		return mServerString.c_str();
	}
	/**
	 * @return a network unique identifier for this Agent.
	 */
	const std::string& getUniqueId() const {
		return mUniqueId;
	}

	tport_t* getIncomingTport(const msg_t* orig) const;
	static sofiasip::TlsConfigInfo getTlsConfigInfo(const GenericStruct* global);
	sip_via_t* getNextVia(sip_t* response) const;

	/**
	 * @return the _default_ bind address for RTP sockets.
	 */
	const std::string& getRtpBindIp(bool ipv6 = false) const {
		return ipv6 ? mRtpBindIp6 : mRtpBindIp;
	}
	const std::string& getPublicIp(bool ipv6 = false) const {
		return ipv6 ? mPublicIpV6 : mPublicIpV4;
	}
	const std::string& getResolvedPublicIp(bool ipv6 = false) const {
		return ipv6 ? mPublicResolvedIpV6 : mPublicResolvedIpV4;
	}

	/**
	 * @return a pair of ip addresses: <public-ip, bind-ip> suitable for destination.
	 */
	std::pair<std::string, std::string> getPreferredIp(const std::string& destination) const;
	/**
	 * @return preferred route for inter-proxy communication.
	 */
	std::string getPreferredRoute() const;
	const url_t* getPreferredRouteUrl() const {
		return mPreferredRouteV4;
	}
	/**
	 * URI associated to this server specifically.
	 */
	const url_t* getNodeUri() const {
		return mNodeUri;
	}
	/**
	 * URI associated to the cluster. It is computed basing on
	 * the cluster domain declared in the cluster section in settings.
	 */
	const url_t* getClusterUri() const {
		return mClusterUri;
	}
	/**
	 * Equal to the node or cluster URI depending on whether cluster mode has
	 * been enabled in settings and a cluster domain has been declared.
	 */
	const url_t* getDefaultUri() const {
		return mDefaultUri;
	}
	tport_t* getInternalTport() const {
		return mInternalTport;
	}

	void setNotifier(const std::weak_ptr<ISupervisorNotifier>& notifier) {
		mNotifier = notifier;
	}

	typedef void (*TimerCallback)(void* unused, su_timer_t* t, void* data);
	su_timer_t* createTimer(int milliseconds, TimerCallback cb, void* data, bool repeating = true) const;
	void stopTimer(su_timer_t* t);

private:
	class Network {
	public:
		Network(const Network& net);
		explicit Network(const struct ifaddrs* ifaddr);

		bool isInNetwork(const struct sockaddr* addr) const;
		static std::string print(const struct ifaddrs* ifaddr);

		const std::string& getIP() const {
			return mIP;
		}

	private:
		struct sockaddr_storage mPrefix {};
		struct sockaddr_storage mMask {};
		std::string mIP{};
	};

	class TlsTransportInfo {
	public:
		TlsTransportInfo(sofiasip::Url url,
		                 sofiasip::TlsConfigInfo tlsConfigInfo,
		                 const std::string& ciphers,
		                 unsigned int tlsPolicy,
		                 std::filesystem::file_time_type lastModificationTime)
		    : url(std::move(url)), tlsConfigInfo(std::move(tlsConfigInfo)), ciphers(ciphers), policy(tlsPolicy),
		      lastModificationTime(lastModificationTime) {}

		sofiasip::Url url;
		sofiasip::TlsConfigInfo tlsConfigInfo;
		std::string ciphers;
		unsigned int policy;
		std::filesystem::file_time_type lastModificationTime;
	};

	static constexpr const char* sInternalTransportIdent = "internal-transport";
	static const std::string sEventSeparator;

	static void printEventTailSeparator();
	static int messageCallback(nta_agent_magic_t* context, nta_agent_t* agent, msg_t* msg, sip_t* sip);

	void loadModules();
	void initializePreferredRoute();
	void onDeclare(const GenericStruct& root);
	void updateTransport(TlsTransportInfo& info);

	void startMdns();
	void startLogWriter();

	template <typename SipEventT, typename ModuleIter>
	std::unique_ptr<SipEventT>
	processEvent(std::unique_ptr<SipEventT>&& ev, const ModuleIter& begin, const ModuleIter& end);
	void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) override;
	void send(const std::shared_ptr<MsgSip>& msg,
	          url_string_t const* u,
	          RequestSipEvent::BeforeSendCallbackList&& callbacks,
	          tag_type_t tag,
	          tag_value_t value,
	          ...) override;
	void reply(const std::shared_ptr<MsgSip>& msg,
	           int status,
	           char const* phrase,
	           tag_type_t tag,
	           tag_value_t value,
	           ...) override;
	int onIncomingMessage(msg_t* msg, const sip_t* sip);

	// Important: placing the SuRoot before the modules ensures it will outlive them, so it is always safe to get (and
	// keep) references to it from within them.
	std::shared_ptr<sofiasip::SuRoot> mRoot = nullptr;
	const std::shared_ptr<ConfigManager> mConfigManager;
	const std::shared_ptr<AuthDb> mAuthDb;
	std::list<std::shared_ptr<Module>> mModules;
	// Important: disconnecting the Redis registrar DB may trigger callbacks on mModules, so they must still be alive
	// when destroying it.
	const std::shared_ptr<RegistrarDb> mRegistrarDb;

	su_home_t mHome{};
	nta_agent_t* mAgent = nullptr;
	nth_engine_t* mHttpEngine = nullptr;
	DomainRegistrationManager* mDrm = nullptr;
	std::unique_ptr<EventLogWriter> mLogWriter;
	std::weak_ptr<ISupervisorNotifier> mNotifier;
	std::shared_ptr<Http2Client> mFlexiApiClient = nullptr;
	std::shared_ptr<NatTraversalStrategy> mNatTraversalStrategy;
#if ENABLE_MDNS
	std::vector<belle_sip_mdns_register_t*> mMdnsRegisterList;
#endif

	sofiasip::Timer mTimer;
	std::optional<sofiasip::Timer> mCertificateUpdateTimer;

	std::string mUniqueId;
	std::string mPassphrase;
	std::string mServerString;
	std::list<std::string> mAliases;

	bool mTerminating = false;
	unsigned int mProxyToProxyKeepAliveInterval = 0;

	std::list<Network> mNetworks;
	std::vector<Transport> mTransports{};
	std::vector<TlsTransportInfo> mTlsTransportsList{};
	std::string mRtpBindIp = "0.0.0.0";
	std::string mRtpBindIp6 = "::0";
	std::string mPublicIpV4;
	std::string mPublicIpV6;
	std::string mPublicResolvedIpV4;
	std::string mPublicResolvedIpV6;
	url_t* mPreferredRouteV4 = nullptr;
	url_t* mPreferredRouteV6 = nullptr;
	const url_t* mNodeUri = nullptr;
	const url_t* mClusterUri = nullptr;
	const url_t* mDefaultUri = nullptr;
	tport_t* mInternalTport = nullptr;

	StatCounter64* mCountIncomingRegister = nullptr;
	StatCounter64* mCountIncomingInvite = nullptr;
	StatCounter64* mCountIncomingAck = nullptr;
	StatCounter64* mCountIncomingInfo = nullptr;
	StatCounter64* mCountIncomingBye = nullptr;
	StatCounter64* mCountIncomingCancel = nullptr;
	StatCounter64* mCountIncomingMessage = nullptr;
	StatCounter64* mCountIncomingNotify = nullptr;
	StatCounter64* mCountIncomingOptions = nullptr;
	StatCounter64* mCountIncomingDecline = nullptr;
	StatCounter64* mCountIncomingReqUnknown = nullptr;

	StatCounter64* mCountIncoming100 = nullptr;
	StatCounter64* mCountIncoming101 = nullptr;
	StatCounter64* mCountIncoming180 = nullptr;
	StatCounter64* mCountIncoming200 = nullptr;
	StatCounter64* mCountIncoming202 = nullptr;
	StatCounter64* mCountIncoming401 = nullptr;
	StatCounter64* mCountIncoming404 = nullptr;
	StatCounter64* mCountIncoming486 = nullptr;
	StatCounter64* mCountIncoming487 = nullptr;
	StatCounter64* mCountIncoming488 = nullptr;
	StatCounter64* mCountIncoming407 = nullptr;
	StatCounter64* mCountIncoming408 = nullptr;
	StatCounter64* mCountIncoming603 = nullptr;
	StatCounter64* mCountIncomingResUnknown = nullptr;

	StatCounter64* mCountReply100 = nullptr;
	StatCounter64* mCountReply101 = nullptr;
	StatCounter64* mCountReply180 = nullptr;
	StatCounter64* mCountReply200 = nullptr;
	StatCounter64* mCountReply202 = nullptr;
	StatCounter64* mCountReply401 = nullptr;
	StatCounter64* mCountReply404 = nullptr;
	StatCounter64* mCountReply486 = nullptr;
	StatCounter64* mCountReply487 = nullptr;
	StatCounter64* mCountReply488 = nullptr;
	StatCounter64* mCountReply407 = nullptr;
	StatCounter64* mCountReply408 = nullptr;
	StatCounter64* mCountReplyResUnknown = nullptr;
};

} // namespace flexisip