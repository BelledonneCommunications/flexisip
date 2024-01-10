/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include <memory>
#include <sstream>
#include <string>

#if defined(HAVE_CONFIG_H) && !defined(FLEXISIP_INCLUDED)
#include "flexisip-config.h"
#define FLEXISIP_INCLUDED
#endif

#if ENABLE_MDNS
#include "belle-sip/belle-sip.h"
#endif

#include "sofia-sip/msg.h"
#include "sofia-sip/nta.h"
#include "sofia-sip/nta_stateless.h"
#include "sofia-sip/nth.h"
#include "sofia-sip/sip.h"
#include "sofia-sip/sip_util.h"

#include "auth/db/authdb.hh"
#include "flexisip/common.hh"
#include "flexisip/configmanager.hh"
#include "flexisip/event.hh"
#include "flexisip/sofia-wrapper/su-root.hh"
#include "flexisip/utils/sip-uri.hh"
#include "registrar/registrar-db.hh"

#include "agent-interface.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "transaction/incoming-agent.hh"
#include "transaction/outgoing-agent.hh"
#include "transaction/transaction.hh"
#include "transport.hh"

namespace flexisip {

class Module;
class NatTraversalStrategy;
class DomainRegistrationManager;

/**
 * The agent class represents a SIP agent.
 * It listens on a UDP and TCP port, receives request and responses,
 * and injects them into the module chain.
 *
 * Refer to the flexisip.conf.sample installed by "make install" for documentation about what each module does.
 **/
class Agent : public AgentInterface,
              public IncomingAgent,
              public OutgoingAgent,
              public ConfigValueListener,
              public std::enable_shared_from_this<Agent> {
	friend class IncomingTransaction;
	friend class OutgoingTransaction;
	friend class Module;

	void onDeclare(const GenericStruct& root);

	StatCounter64* mCountIncomingRegister = nullptr;
	StatCounter64* mCountIncomingInvite = nullptr;
	StatCounter64* mCountIncomingAck = nullptr;
	StatCounter64* mCountIncomingInfo = nullptr;
	StatCounter64* mCountIncomingBye = nullptr;
	StatCounter64* mCountIncomingCancel = nullptr;
	StatCounter64* mCountIncomingMessage = nullptr;
	StatCounter64* mCountIncomingOptions = nullptr;
	StatCounter64* mCountIncomingDecline = nullptr;
	StatCounter64* mCountIncomingReqUnknown = nullptr;

	StatCounter64* mCountIncoming100 = nullptr; // trying
	StatCounter64* mCountIncoming101 = nullptr;
	StatCounter64* mCountIncoming180 = nullptr; // ringing
	StatCounter64* mCountIncoming200 = nullptr; // ok
	StatCounter64* mCountIncoming202 = nullptr;
	StatCounter64* mCountIncoming401 = nullptr; // user auth.
	StatCounter64* mCountIncoming404 = nullptr; // not found
	StatCounter64* mCountIncoming486 = nullptr; // busy
	StatCounter64* mCountIncoming487 = nullptr; // request canceled
	StatCounter64* mCountIncoming488 = nullptr;
	StatCounter64* mCountIncoming407 = nullptr; // proxy auth
	StatCounter64* mCountIncoming408 = nullptr; // request timeout
	StatCounter64* mCountIncoming603 = nullptr; // decline
	StatCounter64* mCountIncomingResUnknown = nullptr;

	StatCounter64* mCountReply100 = nullptr; // trying
	StatCounter64* mCountReply101 = nullptr;
	StatCounter64* mCountReply180 = nullptr; // ringing
	StatCounter64* mCountReply200 = nullptr; // ok
	StatCounter64* mCountReply202 = nullptr;
	StatCounter64* mCountReply401 = nullptr; // user auth.
	StatCounter64* mCountReply404 = nullptr; // not found
	StatCounter64* mCountReply486 = nullptr; // busy
	StatCounter64* mCountReply487 = nullptr; // request canceled
	StatCounter64* mCountReply488 = nullptr;
	StatCounter64* mCountReply407 = nullptr; // proxy auth
	StatCounter64* mCountReply408 = nullptr; // request timeout
	StatCounter64* mCountReplyResUnknown = nullptr;

private:
	template <typename SipEventT, typename ModuleIter>
	void doSendEvent(std::shared_ptr<SipEventT> ev, const ModuleIter& begin, const ModuleIter& end);

public:
	Agent(const std::shared_ptr<sofiasip::SuRoot>& root,
	      const std::shared_ptr<ConfigManager>& cm,
	      const std::shared_ptr<AuthDbBackendOwner>& authDbOwner,
	      const std::shared_ptr<RegistrarDb>& registrarDb);

	void start(const std::string& transport_override, const std::string& passphrase);
	void unloadConfig();
	~Agent() override;
	// Add agent and modules sections
	static void addConfigSections(ConfigManager& cfg);
	// Load plugins and add their sections
	static void addPluginsConfigSections(ConfigManager& cfg);
	/// Returns a pair of ip addresses: < public-ip, bind-ip> suitable for destination.
	std::pair<std::string, std::string> getPreferredIp(const std::string& destination) const;
	/// Returns the _default_ bind address for RTP sockets.
	const std::string& getRtpBindIp(bool ipv6 = false) const {
		return ipv6 ? mRtpBindIp6 : mRtpBindIp;
	}
	const std::string& getPublicIp(bool ipv6 = false) const {
		return ipv6 ? mPublicIpV6 : mPublicIpV4;
	}
	const std::string& getResolvedPublicIp(bool ipv6 = false) const {
		return ipv6 ? mPublicResolvedIpV6 : mPublicResolvedIpV4;
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
	AuthDbBackendOwner& getAuthDbOwner() {
		return *mAuthDbOwner;
	}
	RegistrarDb& getRegistrarDb() {
		return *mRegistrarDb;
	}

	// Preferred route for inter-proxy communication
	std::string getPreferredRoute() const;
	const url_t* getPreferredRouteUrl() const {
		return mPreferredRouteV4;
	}
	tport_t* getInternalTport() const {
		return mInternalTport;
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
	/**
	 * return a network unique identifier for this Agent.
	 */
	const std::string& getUniqueId() const;

	const std::shared_ptr<NatTraversalStrategy>& getNatTraversalStrategy() const {
		return mNatTraversalStrategy;
	}

	EventLogWriter* getEventLogWriter() const {
		return mLogWriter.get();
	}
	void setEventLogWriter(std::unique_ptr<EventLogWriter>&& value) {
		mLogWriter = std::move(value);
	}

	void idle();
	bool isUs(const url_t* url, bool check_aliases = true) const;
	const std::shared_ptr<sofiasip::SuRoot>& getRoot() const noexcept override {
		return mRoot;
	}
	nta_agent_t* getSofiaAgent() const override {
		return mAgent;
	}
	int countUsInVia(sip_via_t* via) const;
	bool isUs(const char* host, const char* port, bool check_aliases) const;
	sip_via_t* getNextVia(sip_t* response);
	const char* getServerString() const;
	typedef void (*TimerCallback)(void* unused, su_timer_t* t, void* data);
	su_timer_t* createTimer(int milliseconds, TimerCallback cb, void* data, bool repeating = true);
	void stopTimer(su_timer_t* t);
	void injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev) override;
	void injectResponseEvent(const std::shared_ptr<ResponseSipEvent>& ev) override;
	void sendRequestEvent(std::shared_ptr<RequestSipEvent> ev);
	void sendResponseEvent(const std::shared_ptr<ResponseSipEvent>& ev) override;
	void incrReplyStat(int status);
	bool doOnConfigStateChanged(const ConfigValue& conf, ConfigState state) override;
	std::shared_ptr<Module> findModule(const std::string& moduleName) const;
	std::shared_ptr<Module> findModuleByFunction(const std::string& moduleFunction) const;
	nth_engine_t* getHttpEngine() {
		return mHttpEngine;
	}
	DomainRegistrationManager* getDRM() {
		return mDrm;
	}
	url_t* urlFromTportName(su_home_t* home, const tp_name_t* name);
	void applyProxyToProxyTransportSettings(tport_t* tp);
	tport_t* getIncomingTport(const msg_t* orig);

	static sofiasip::TlsConfigInfo getTlsConfigInfo(const GenericStruct* global);

	bool shouldUseRfc2543RecordRoute() const;

	const ConfigManager& getConfigManager() const {
		return *mConfigManager;
	}

	void sendTrap(const GenericEntry* source, const std::string& msg) {
		mConfigManager->sendTrap(source, msg);
	}

private:
	// Private types
	class Network {
		struct sockaddr_storage mPrefix;
		struct sockaddr_storage mMask;
		std::string mIP;

	public:
		Network(const Network& net);
		Network(const struct ifaddrs* ifaddr);
		bool isInNetwork(const struct sockaddr* addr) const;
		const std::string getIP() const;
		static std::string print(const struct ifaddrs* ifaddr);
	};

	// Private methods
	int onIncomingMessage(msg_t* msg, const sip_t* sip);
	void
	send(const std::shared_ptr<MsgSip>& msg, url_string_t const* u, tag_type_t tag, tag_value_t value, ...) override;
	void reply(const std::shared_ptr<MsgSip>& msg,
	           int status,
	           char const* phrase,
	           tag_type_t tag,
	           tag_value_t value,
	           ...) override;
	void discoverInterfaces();
	void startLogWriter();
	std::string computeResolvedPublicIp(const std::string& host, int family = AF_UNSPEC) const;
	void checkAllowedParams(const url_t* uri);
	void initializePreferredRoute();
	void loadModules();
	void startMdns();

	static int messageCallback(nta_agent_magic_t* context, nta_agent_t* agent, msg_t* msg, sip_t* sip);
	static void printEventTailSeparator();

	// Private attributes
	std::string mServerString;
	// Placing the SuRoot before the modules ensures it will outlive them, so it is always safe to get (and keep)
	// references to it from within them
	std::shared_ptr<sofiasip::SuRoot> mRoot = nullptr;
	const std::shared_ptr<ConfigManager> mConfigManager;
	const std::shared_ptr<AuthDbBackendOwner> mAuthDbOwner;
	const std::shared_ptr<RegistrarDb> mRegistrarDb;
	std::list<std::shared_ptr<Module>> mModules;
	std::shared_ptr<NatTraversalStrategy> mNatTraversalStrategy;
	std::list<std::string> mAliases;
	url_t* mPreferredRouteV4 = nullptr;
	url_t* mPreferredRouteV6 = nullptr;
	const url_t* mNodeUri = nullptr;
	const url_t* mClusterUri = nullptr;
	const url_t* mDefaultUri = nullptr;
	std::list<Network> mNetworks;
	std::string mUniqueId;
	std::string mRtpBindIp = "0.0.0.0";
	std::string mRtpBindIp6 = "::0";
	std::string mPublicIpV4, mPublicIpV6, mPublicResolvedIpV4, mPublicResolvedIpV6;
	std::vector<Transport> mTransports{};
	nta_agent_t* mAgent = nullptr;
	nth_engine_t* mHttpEngine = nullptr;
	su_home_t mHome;
	su_timer_t* mTimer = nullptr;
	unsigned int mProxyToProxyKeepAliveInterval = 0;
	std::unique_ptr<EventLogWriter> mLogWriter;
	DomainRegistrationManager* mDrm = nullptr;
	std::string mPassphrase;
	tport_t* mInternalTport = nullptr;
	bool mTerminating = false;
#if ENABLE_MDNS
	std::vector<belle_sip_mdns_register_t*> mMdnsRegisterList;
#endif
	bool mUseRfc2543RecordRoute = false;

	static constexpr const char* sInternalTransportIdent = "internal-transport";
	static const std::string sEventSeparator;
};

} // namespace flexisip
