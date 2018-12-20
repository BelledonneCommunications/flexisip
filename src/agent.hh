/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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

#ifndef agent_hh
#define agent_hh

#if defined(HAVE_CONFIG_H) && !defined(FLEXISIP_INCLUDED)
#include "flexisip-config.h"
#define FLEXISIP_INCLUDED
#endif

#include <string>
#include <sstream>
#include <memory>

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/nta_stateless.h>
#include <sofia-sip/nth.h>

#include "common.hh"
#include "configmanager.hh"
#include "event.hh"
#include "transaction.hh"
#include "eventlogs/eventlogs.hh"

#if ENABLE_MDNS
#include "belle-sip/belle-sip.h"
#endif

class Module;
class DomainRegistrationManager;

/**
 * The agent class represents a SIP agent.
 * It listens on a UDP and TCP port, receives request and responses,
 * and injects them into the module chain.
 *
 * Refer to the flexisip.conf.sample installed by "make install" for documentation about what each module does.
**/
class Agent : public IncomingAgent,
			  public OutgoingAgent,
			  public std::enable_shared_from_this<Agent>,
			  public ConfigValueListener {
	friend class IncomingTransaction;
	friend class OutgoingTransaction;
	friend class Module;

	StatCounter64 *mCountIncomingRegister = nullptr;
	StatCounter64 *mCountIncomingInvite = nullptr;
	StatCounter64 *mCountIncomingAck = nullptr;
	StatCounter64 *mCountIncomingInfo = nullptr;
	StatCounter64 *mCountIncomingBye = nullptr;
	StatCounter64 *mCountIncomingCancel = nullptr;
	StatCounter64 *mCountIncomingMessage = nullptr;
	StatCounter64 *mCountIncomingOptions = nullptr;
	StatCounter64 *mCountIncomingDecline = nullptr;
	StatCounter64 *mCountIncomingReqUnknown = nullptr;

	StatCounter64 *mCountIncoming100 = nullptr; // trying
	StatCounter64 *mCountIncoming101 = nullptr;
	StatCounter64 *mCountIncoming180 = nullptr; // ringing
	StatCounter64 *mCountIncoming200 = nullptr; // ok
	StatCounter64 *mCountIncoming202 = nullptr;
	StatCounter64 *mCountIncoming401 = nullptr; // user auth.
	StatCounter64 *mCountIncoming404 = nullptr; // not found
	StatCounter64 *mCountIncoming486 = nullptr; // busy
	StatCounter64 *mCountIncoming487 = nullptr; // request canceled
	StatCounter64 *mCountIncoming488 = nullptr;
	StatCounter64 *mCountIncoming407 = nullptr; // proxy auth
	StatCounter64 *mCountIncoming408 = nullptr; // request timeout
	StatCounter64 *mCountIncoming603 = nullptr; // decline
	StatCounter64 *mCountIncomingResUnknown = nullptr;

	StatCounter64 *mCountReply100 = nullptr; // trying
	StatCounter64 *mCountReply101 = nullptr;
	StatCounter64 *mCountReply180 = nullptr; // ringing
	StatCounter64 *mCountReply200 = nullptr; // ok
	StatCounter64 *mCountReply202 = nullptr;
	StatCounter64 *mCountReply401 = nullptr; // user auth.
	StatCounter64 *mCountReply404 = nullptr; // not found
	StatCounter64 *mCountReply486 = nullptr; // busy
	StatCounter64 *mCountReply487 = nullptr; // request canceled
	StatCounter64 *mCountReply488 = nullptr;
	StatCounter64 *mCountReply407 = nullptr; // proxy auth
	StatCounter64 *mCountReply408 = nullptr; // request timeout
	StatCounter64 *mCountReplyResUnknown = nullptr;
	void onDeclare(GenericStruct *root);
	ConfigValueListener *mBaseConfigListener = nullptr;

private:
	template <typename SipEventT>
	void doSendEvent(std::shared_ptr<SipEventT> ev, const std::list<std::unique_ptr<Module>>::iterator &begin,
					 const std::list<std::unique_ptr<Module>>::iterator &end);

public:
	Agent(su_root_t *root);
	void start(const std::string &transport_override, const std::string passphrase);
	virtual void loadConfig(GenericManager *cm);
	virtual void unloadConfig();
	virtual ~Agent();
	/// Returns a pair of ip addresses: < public-ip, bind-ip> suitable for destination.
	std::pair<std::string, std::string> getPreferredIp(const std::string &destination) const;
	/// Returns the _default_ bind address for RTP sockets.
	const std::string &getRtpBindIp(bool ipv6 = false) const {
		return ipv6 ? mRtpBindIp6 : mRtpBindIp;
	}
	const std::string &getPublicIp(bool ipv6 = false) const {
		return ipv6 ? mPublicIpV6 : mPublicIpV4;
	}
	const std::string &getResolvedPublicIp(bool ipv6 = false) const {
		return ipv6 ? mPublicResolvedIpV6 : mPublicResolvedIpV4;
	}
	virtual Agent *getAgent() {
		return this;
	}
	// Preferred route for inter-proxy communication
	std::string getPreferredRoute() const;
	const url_t *getPreferredRouteUrl() const {
		return mPreferredRouteV4;
	}
	/**
	 * URI associated to this server specifically.
	 */
	const url_t *getNodeUri() const {
		return mNodeUri;
	}
	/**
	 * URI associated to the cluster. It is computed basing on
	 * the cluster domain declared in the cluster section in settings.
	 */
	const url_t *getClusterUri() const {
		return mClusterUri;
	}
	/**
	 * Equal to the node or cluster URI depending on whether cluster mode has
	 * been enabled in settings and a cluster domain has been decladed.
	 */
	const url_t *getDefaultUri() const {
		return mDefaultUri;
	}
	/**
	 * return a network unique identifier for this Agent.
	 */
	const std::string &getUniqueId() const;
	void idle();
	bool isUs(const url_t *url, bool check_aliases = true) const;
	su_root_t *getRoot() const {
		return mRoot;
	}
	nta_agent_t *getSofiaAgent() const {
		return mAgent;
	}
	int countUsInVia(sip_via_t *via) const;
	bool isUs(const char *host, const char *port, bool check_aliases) const;
	sip_via_t *getNextVia(sip_t *response);
	const char *getServerString() const;
	typedef void (*timerCallback)(void *unused, su_timer_t *t, void *data);
	su_timer_t *createTimer(int milliseconds, timerCallback cb, void *data, bool repeating=true);
	void stopTimer(su_timer_t *t);
	void injectRequestEvent(std::shared_ptr<RequestSipEvent> ev);
	void injectResponseEvent(std::shared_ptr<ResponseSipEvent> ev);
	void sendRequestEvent(std::shared_ptr<RequestSipEvent> ev);
	void sendResponseEvent(std::shared_ptr<ResponseSipEvent> ev);
	void incrReplyStat(int status);
	bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);
	void logEvent(const std::shared_ptr<SipEvent> &ev);
	Module *findModule(const std::string &moduleName) const;
	nth_engine_t *getHttpEngine() {
		return mHttpEngine;
	}
	DomainRegistrationManager *getDRM() {return mDrm.get();}
	url_t* urlFromTportName(su_home_t* home, const tp_name_t* name, bool avoidMAddr = false);
	void applyProxyToProxyTransportSettings(tport_t *tp);
private:
	int onIncomingMessage(msg_t *msg, const sip_t *sip);
	virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
	virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);
	void discoverInterfaces();
	void startLogWriter();
	std::string computeResolvedPublicIp(const std::string &host, int family = AF_UNSPEC) const;
	void checkAllowedParams(const url_t *uri);
	void initializePreferredRoute();
	void loadModules();
	void startMdns();

	std::string mServerString;
	std::list<std::unique_ptr<Module>> mModules;
	std::list<std::string> mAliases;
	url_t *mPreferredRouteV4 = nullptr;
	url_t *mPreferredRouteV6 = nullptr;
	const url_t *mNodeUri = nullptr;
	const url_t *mClusterUri = nullptr;
	const url_t *mDefaultUri = nullptr;
	class Network {
	public:
		Network(const Network &net);
		Network(const struct ifaddrs *ifaddr);

		const std::string &getIp() const {return mIp;}

		bool isInNetwork(const struct sockaddr *addr) const;

		static std::string print(const struct ifaddrs *ifaddr);

	private:
		struct sockaddr_storage mPrefix;
		struct sockaddr_storage mMask;
		std::string mIp;
	};
	std::list<Network> mNetworks;
	std::string mUniqueId;
	std::string mRtpBindIp, mRtpBindIp6, mPublicIpV4, mPublicIpV6, mPublicResolvedIpV4, mPublicResolvedIpV6;
	nta_agent_t *mAgent = nullptr;
	su_root_t *mRoot = nullptr;
	nth_engine_t *mHttpEngine = nullptr;
	su_home_t mHome;
	unsigned int mProxyToProxyKeepAliveInterval = 0;
	EventLogWriter *mLogWriter = nullptr;
	std::unique_ptr<DomainRegistrationManager> mDrm;
	std::string mPassphrase;
	static int messageCallback(nta_agent_magic_t *context, nta_agent_t *agent, msg_t *msg, sip_t *sip);
	bool mTerminating = false;
	bool mUseMaddr = false;
#if ENABLE_MDNS
	std::vector<belle_sip_mdns_register_t *> mMdnsRegisterList;
#endif
};

#endif
