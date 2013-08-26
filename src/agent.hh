/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

class Module;

/**
 * The agent class represents a SIP agent.
 * It listens on a UDP and TCP port, receives request and responses, 
 * and injects them into the module chain.
 * The module chain is :
 * NatHelper => Authentication => Registrar => ContactRouteInserter => MediaRelay => Transcoder => Forward
 * 
 * Refer to the flexisip.conf.sample installed by "make install" for documentation about what each module does.
**/
class Agent: public IncomingAgent, public OutgoingAgent, public std::enable_shared_from_this<Agent>, public ConfigValueListener {
	friend class IncomingTransaction;
	friend class OutgoingTransaction;
	friend class StatelessSipEvent;
	friend class StatefulSipEvent;
	friend class Module;


	StatCounter64 *mCountIncomingRegister;
	StatCounter64 *mCountIncomingInvite;
	StatCounter64 *mCountIncomingAck;
	StatCounter64 *mCountIncomingInfo;
	StatCounter64 *mCountIncomingBye;
	StatCounter64 *mCountIncomingCancel;
	StatCounter64 *mCountIncomingMessage;
	StatCounter64 *mCountIncomingOptions;
	StatCounter64 *mCountIncomingDecline;
	StatCounter64 *mCountIncomingReqUnknown;

	StatCounter64 *mCountIncoming100; // trying
	StatCounter64 *mCountIncoming101;
	StatCounter64 *mCountIncoming180; // ringing
	StatCounter64 *mCountIncoming200; // ok
	StatCounter64 *mCountIncoming202;
	StatCounter64 *mCountIncoming401; // user auth.
	StatCounter64 *mCountIncoming404; // not found
	StatCounter64 *mCountIncoming486; // busy
	StatCounter64 *mCountIncoming487; // request canceled
	StatCounter64 *mCountIncoming488;
	StatCounter64 *mCountIncoming407; // proxy auth
	StatCounter64 *mCountIncoming408; // request timeout
	StatCounter64 *mCountIncoming603; // decline
	StatCounter64 *mCountIncomingResUnknown;

	StatCounter64 *mCountReply100; // trying
	StatCounter64 *mCountReply101;
	StatCounter64 *mCountReply180; // ringing
	StatCounter64 *mCountReply200; // ok
	StatCounter64 *mCountReply202;
	StatCounter64 *mCountReply401; // user auth.
	StatCounter64 *mCountReply404; // not found
	StatCounter64 *mCountReply486; // busy
	StatCounter64 *mCountReply487; // request canceled
	StatCounter64 *mCountReply488;
	StatCounter64 *mCountReply407; // proxy auth
	StatCounter64 *mCountReply408; // request timeout
	StatCounter64 *mCountReplyResUnknown;
	void onDeclare(GenericStruct *root);
	ConfigValueListener *mBaseConfigListener;

	private:
	template <typename SipEventT>
	void doSendEvent
	(std::shared_ptr<SipEventT> ev, const std::list<Module *>::iterator &begin, const std::list<Module *>::iterator &end);
	public:
		Agent(su_root_t *root);
		void start(const char *transport_override);
		virtual void loadConfig(GenericManager *cm);
		virtual ~Agent();
		///Returns a pair of ip addresses: < public-ip, bind-ip> suitable for destination. 
		std::pair<std::string,std::string> getPreferredIp(const std::string &destination) const;
		///Returns the _default_ bind address for RTP sockets.
		const std::string &getRtpBindIp(bool ipv6=false)const{
			return ipv6 ? mRtpBindIp6 : mRtpBindIp;
		}
		const std::string &getPublicIp(bool ipv6=false)const{
			return ipv6 ? mPublicIpV6 : mPublicIpV4;
		}
		virtual Agent *getAgent() {
			return this;
		}
		//Preferred route for inter-proxy communication
		std::string getPreferredRoute()const;
		const url_t *getPreferredRouteUrl()const{
			return mPreferredRouteV4;
		}
		/**
		 * return a network unique identifier for this Agent.
		 */
		const std::string& getUniqueId() const;
		void idle();
		bool isUs(const url_t *url, bool check_aliases=true)const;
		su_root_t *getRoot() const{
			return mRoot;
		}
		nta_agent_t *getSofiaAgent()const{
			return mAgent;
		}
		int countUsInVia(sip_via_t *via)const;
		bool isUs(const char *host, const char *port, bool check_aliases)const;
		sip_via_t *getNextVia(sip_t *response);
		const char *getServerString()const;
		typedef void (*timerCallback)(void *unused, su_timer_t *t, void *data);
		su_timer_t *createTimer(int milliseconds, timerCallback cb, void *data);
		void stopTimer(su_timer_t *t);
		void injectRequestEvent(std::shared_ptr<RequestSipEvent> ev);
		void injectResponseEvent(std::shared_ptr<ResponseSipEvent> ev);
		void sendRequestEvent(std::shared_ptr<RequestSipEvent> ev);
		void sendResponseEvent(std::shared_ptr<ResponseSipEvent> ev);
		void incrReplyStat(int status);
		bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);
		void logEvent(const std::shared_ptr<SipEvent> &ev);
		Module *findModule(const std::string &modname) const;
		nth_engine_t* getHttpEngine() {return mHttpEngine; }
	protected:
		void sendTransactionEvent(std::shared_ptr<TransactionEvent> ev);
		int onIncomingMessage(msg_t *msg, sip_t *sip);
	private:
		virtual void send(const std::shared_ptr<MsgSip> &msg, url_string_t const *u, tag_type_t tag, tag_value_t value, ...);
		virtual void reply(const std::shared_ptr<MsgSip> &msg, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...);
		void discoverInterfaces();
		void startLogWriter();
		std::string mServerString;
		std::list<Module*> mModules;
		std::list<std::string> mAliases;
		url_t *mPreferredRouteV4;
		url_t *mPreferredRouteV6;
		class Network {
			struct sockaddr_storage mNetwork;
			std::string mIP;
		public:
			Network(const Network &net);
			Network(const struct ifaddrs *ifaddr);
			bool isInNetwork(const struct sockaddr *addr) const;
			const std::string getIP() const;
			static std::string print(const struct ifaddrs *ifaddr);
		};
		std::list<Network> mNetworks;
		std::string mUniqueId;
		std::string mRtpBindIp,mRtpBindIp6,mPublicIpV4,mPublicIpV6;
		nta_agent_t *mAgent;
		su_root_t *mRoot;
		nth_engine_t *mHttpEngine;
		su_home_t mHome;
		EventLogWriter *mLogWriter;
		static int messageCallback(nta_agent_magic_t *context, nta_agent_t *agent,msg_t *msg,sip_t *sip);
		bool mTerminating;
};

#endif

