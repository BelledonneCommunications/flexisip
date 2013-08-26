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
 +*/

#if defined(HAVE_CONFIG_H) && !defined(FLEXISIP_INCLUDED)
#include "flexisip-config.h"
#define FLEXISIP_INCLUDED
#endif
#include "agent.hh"
#include "module.hh"

#include "log/logmanager.hh"
#include "sipattrextractor.hh"

#include "etchosts.hh"
#include <algorithm>
#include <sstream>
#include <sofia-sip/tport_tag.h>
#include <sofia-sip/su_tagarg.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/tport.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <net/if.h>
#include <ifaddrs.h>

#define IPADDR_SIZE 64

using namespace ::std;

static StatCounter64 *createCounter(GenericStruct *global, string keyprefix, string helpprefix, string value) {
	return global->createStat(keyprefix+value, helpprefix + value +".");
}
void Agent::onDeclare(GenericStruct *root) {
	GenericStruct *global=root->get<GenericStruct>("global");
	string key="count-incoming-request-";
	string help="Number of incoming requests with method name ";
	mCountIncomingRegister=createCounter(global,key, help, "register");
	mCountIncomingInvite=createCounter(global,key, help, "invite");
	mCountIncomingAck=createCounter(global,key, help, "ack");
	mCountIncomingInfo=createCounter(global,key, help, "info");
	mCountIncomingBye=createCounter(global,key, help, "bye");
	mCountIncomingCancel=createCounter(global,key, help, "cancel");
	mCountIncomingMessage=createCounter(global,key, help, "message");
	mCountIncomingDecline=createCounter(global,key, help, "decline");
	mCountIncomingOptions=createCounter(global,key, help, "options");
	mCountIncomingReqUnknown=createCounter(global,key, help, "unknown");

	key="count-incoming-response-";
	help= "Number of incoming response with status ";
	mCountIncoming100=createCounter(global,key, help, "100");
	mCountIncoming101=createCounter(global,key, help, "101");
	mCountIncoming180=createCounter(global,key, help, "180");
	mCountIncoming200=createCounter(global,key, help, "200");
	mCountIncoming202=createCounter(global,key, help, "202");
	mCountIncoming401=createCounter(global,key, help, "401");
	mCountIncoming404=createCounter(global,key, help, "404");
	mCountIncoming407=createCounter(global,key, help, "407");
	mCountIncoming408=createCounter(global,key, help, "408");
	mCountIncoming486=createCounter(global,key, help, "486");
	mCountIncoming487=createCounter(global,key, help, "487");
	mCountIncoming488=createCounter(global,key, help, "488");
	mCountIncoming603=createCounter(global,key, help, "603");
	mCountIncomingResUnknown=createCounter(global,key, help, "unknown");

	key="count-reply-";
	help="Number of replied ";
	mCountReply100=createCounter(global,key, help, "100");
	mCountReply101=createCounter(global,key, help, "101");
	mCountReply180=createCounter(global,key, help, "180");
	mCountReply200=createCounter(global,key, help, "200");
	mCountReply202=createCounter(global,key, help, "202");
	mCountReply401=createCounter(global,key, help, "401");
	mCountReply404=createCounter(global,key, help, "404");
	mCountReply407=createCounter(global,key, help, "407");
	mCountReply408=createCounter(global,key, help, "408"); // request timeout
	mCountReply486=createCounter(global,key, help, "486");
	mCountReply487=createCounter(global,key, help, "487"); // Request canceled
	mCountReply488=createCounter(global,key, help, "488");
	mCountReplyResUnknown=createCounter(global,key, help, "unknown");
	mLogWriter=NULL;
}

void Agent::startLogWriter(){
	GenericStruct *cr=GenericManager::get()->getRoot();
	bool enabled=cr->get<GenericStruct>("global")->get<ConfigBoolean>("enable-event-logs")->read();
	string logdir=cr->get<GenericStruct>("global")->get<ConfigString>("event-logs-dir")->read();
	if (enabled){
		FilesystemEventLogWriter *lw=new FilesystemEventLogWriter(logdir);
		if (!lw->isReady()){
			delete lw;
		}else mLogWriter=lw;
	}
}

void Agent::start(const char *transport_override){
	GenericStruct *cr=GenericManager::get()->getRoot();
	list<string> transports=cr->get<GenericStruct>("global")->get<ConfigStringList>("transports")->read();
	int tports_idle_timeout=cr->get<GenericStruct>("global")->get<ConfigInt>("idle-timeout")->read();
	
	tports_idle_timeout*=1000; //sofia needs a value in millseconds.
	
	if (transport_override){
		transports=ConfigStringList::parse(transport_override);
	}

	for(auto it=transports.begin();it!=transports.end();++it){
		const string &uri=(*it);
		url_t *url;
		int err;
		su_home_t home;
		su_home_init(&home);
		url=url_make(&home,uri.c_str());
		LOGD("Enabling transport %s",uri.c_str());
		if (uri.find("sips")==0){
			string keys = cr->get<GenericStruct>("global")->get<ConfigString>("tls-certificates-dir")->read();
			err=nta_agent_add_tport(mAgent,(const url_string_t*)url,TPTAG_CERTIFICATE(keys.c_str()), NTATAG_TLS_RPORT(1), TPTAG_IDLE(tports_idle_timeout), TAG_END());
		}else{
			err=nta_agent_add_tport(mAgent,(const url_string_t*)url,NTATAG_CLIENT_RPORT(1), TPTAG_IDLE(tports_idle_timeout), TAG_END());
		}
		if (err==-1){
			LOGE("Could not enable transport %s: %s",uri.c_str(),strerror(errno));
		}
		su_home_deinit(&home);
	}
	
	tport_t *primaries=tport_primaries(nta_agent_tports(mAgent));
	if (primaries==NULL) LOGF("No sip transport defined.");
	su_md5_t ctx;
	su_md5_init(&ctx);

	LOGD("Agent 's primaries are:");
	for(tport_t *tport=primaries;tport!=NULL;tport=tport_next(tport)){
		const tp_name_t *name;
		char url[512];
		name=tport_name(tport);
		snprintf(url,sizeof(url),"sip:%s:%s;transport=%s,maddr=%s",name->tpn_canon,name->tpn_port,name->tpn_proto,name->tpn_host);
		su_md5_strupdate(&ctx,url);
		LOGD("\t%s",url);
		bool isIpv6=strchr(name->tpn_host, ':') != NULL;
		if (strcmp(name->tpn_canon,name->tpn_host)!=0) {
			// The public and bind values are different
			// which is the case of transport with sip:public;maddr=bind
			// where public is the hostname or ip address publicly announced
			// and maddr the real ip we listen on.
			// Useful for a scenario where the flexisip is behind a router.
			if (isIpv6 && mPublicIpV6.empty()) {
				mPublicIpV6=name->tpn_canon;
				//LOGD("\tIpv6 public ip is %s", mPublicIpV6.c_str());
			} else if (!isIpv6 && mPublicIpV4.empty()) {
				mPublicIpV4=name->tpn_canon;
				//LOGD("\tIpv4 public ip %s", mPublicIpV4.c_str());
			}
		}
		url_t **preferred=isIpv6?&mPreferredRouteV6:&mPreferredRouteV4;
		if (*preferred == NULL) {
			tp_name_t tp_priv_name=*name;
			tp_priv_name.tpn_canon=tp_priv_name.tpn_host;
			*preferred=ModuleToolbox::urlFromTportName(&mHome,&tp_priv_name);
			//char prefUrl[266];
			//url_e(prefUrl,sizeof(prefUrl),*preferred);
			//LOGD("\tDetected %s preferred route to %s", isIpv6 ? "ipv6":"ipv4", prefUrl);
		}
	}
	
	if (mPublicIpV4.empty() && mPreferredRouteV4) mPublicIpV4=mPreferredRouteV4->url_host;
	if (mPublicIpV6.empty() && mPreferredRouteV6) mPublicIpV6=mPreferredRouteV6->url_host;
	
	if (mPreferredRouteV4) {
		mRtpBindIp=mPreferredRouteV4->url_host;
	}
	if (mPreferredRouteV6) {
		mRtpBindIp6=mPreferredRouteV6->url_host;
	}
	
	if (mRtpBindIp.empty()) mRtpBindIp="0.0.0.0";
	if (mRtpBindIp6.empty()) mRtpBindIp6="::0";
	
	char digest[(SU_MD5_DIGEST_SIZE*2)+1];
	su_md5_hexdigest(&ctx,digest);
	su_md5_deinit(&ctx);
	digest[16]='\0';//keep half of the digest, should be enough
	// compute a network wide unique id
	mUniqueId = digest;
	
	LOGD("Agent public hostname/ip %s (v6: %s)",mPublicIpV4.c_str(), mPublicIpV6.c_str());
	LOGD("Agent's _default_ RTP bind ip address is %s (v6: %s)",mRtpBindIp.c_str(),mRtpBindIp6.c_str());
	
	char prefUrl4[256]={0};
	char prefUrl6[256]={0};
	if (mPreferredRouteV4) url_e(prefUrl4,sizeof(prefUrl4),mPreferredRouteV4);
	if (mPreferredRouteV6) url_e(prefUrl6,sizeof(prefUrl6),mPreferredRouteV6);
	LOGD("Agent's preferred IP for internal routing is %s (v6: %s)",prefUrl4,prefUrl6);
	
	startLogWriter();
}

Agent::Agent(su_root_t* root):mBaseConfigListener(NULL), mTerminating(false){
	mHttpEngine = nth_engine_create(root, NTHTAG_ERROR_MSG(0), TAG_END());
	GenericStruct *cr = GenericManager::get()->getRoot();
	
	EtcHostsResolver::get();

	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "GarbageIn"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "NatHelper"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Authentication"));
#ifdef HAVE_DATEHANDLER
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "DateHandler"));
#endif
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "GatewayAdapter"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Registrar"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "ContactRouteInserter"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Router"));
#ifdef ENABLE_PUSHNOTIFICATION
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "PushNotification"));
#endif
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "LoadBalancer"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "MediaRelay"));
#ifdef ENABLE_TRANSCODER
	const auto &overrideMap=GenericManager::get()->getOverrideMap();
	if (overrideMap.find("notrans") == overrideMap.end()) {
		mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"Transcoder"));
	}
#endif
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Forward"));

	mServerString = "Flexisip/"
	VERSION
	" (sofia-sip-nta/" NTA_VERSION ")";

	for_each(mModules.begin(), mModules.end(), bind2nd(mem_fun(&Module::declare), cr));
	onDeclare(cr);

	struct ifaddrs *net_addrs;
	int err = getifaddrs(&net_addrs);
	if (err == 0) {
		struct ifaddrs * ifa = net_addrs;
		while (ifa != NULL) {
			if (ifa->ifa_netmask != NULL && ifa->ifa_addr != NULL) {
				LOGD("New network: %s", Network::print(ifa).c_str());
				mNetworks.push_front(Network(ifa));
			}
			ifa = ifa->ifa_next;
		}
		freeifaddrs(net_addrs);
	} else {
		LOGE("Can't find interface addresses: %s", strerror(err));
	}
	mRoot = root;
	mAgent = nta_agent_create(root, (url_string_t*) -1, &Agent::messageCallback, (nta_agent_magic_t*) this, NTATAG_UDP_MTU(1460), TAG_END());
	su_home_init(&mHome);
	mPreferredRouteV4=NULL;
	mPreferredRouteV6=NULL;
}

Agent::~Agent() {
	mTerminating=true;
	for_each(mModules.begin(), mModules.end(), delete_functor<Module>());
	if (mAgent)	nta_agent_destroy(mAgent);
	if (mHttpEngine) nth_engine_destroy(mHttpEngine);
	su_home_deinit(&mHome);
}

const char *Agent::getServerString() const {
	return mServerString.c_str();
}

std::string Agent::getPreferredRoute()const{
	char prefUrl[266];
	url_e(prefUrl,sizeof(prefUrl),mPreferredRouteV4);
	return string(prefUrl);
}

bool Agent::doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) {
	LOGD("Configuration of agent changed for key %s to %s",
			conf.getName().c_str(), conf.get().c_str());

	if (conf.getName() == "aliases" && state == ConfigState::Commited) {
		mAliases=((ConfigStringList*)(&conf))->read();
		LOGD("Global aliases updated");
		return true;
	}

	return mBaseConfigListener->onConfigStateChanged(conf, state);
}

void Agent::loadConfig(GenericManager *cm) {
	cm->loadStrict(); //now that each module has declared its settings, we need to reload from the config file
	if (!mBaseConfigListener) {
		mBaseConfigListener=cm->getGlobal()->getConfigListener();
	}
	cm->getRoot()->get<GenericStruct>("global")->setConfigListener(this);
	mAliases = cm->getGlobal()->get<ConfigStringList>("aliases")->read();
	LOGD("List of host aliases:");
	for (list<string>::iterator it = mAliases.begin(); it != mAliases.end(); ++it) {
		LOGD("%s", (*it).c_str());
	}
	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		// Check in all cases, even if not enabled,
		// to allow safe dynamic activation of the module
		(*it)->checkConfig();
		(*it)->load();
	}
}


std::pair<std::string,std::string> Agent::getPreferredIp(const std::string &destination) const {
	int err;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;

	struct addrinfo *result;
	err = getaddrinfo(destination.c_str(), NULL, &hints, &result);
	if (err == 0) {
		for (auto it = mNetworks.begin(); it != mNetworks.end(); ++it) {
			if (it->isInNetwork(result->ai_addr)) {
				freeaddrinfo(result);
				return make_pair(it->getIP(),it->getIP());
			}
		}
		freeaddrinfo(result);
	} else {
		LOGE("getaddrinfo error: %s", strerror(errno));
	}
	return strchr(destination.c_str(),':')==NULL ? make_pair(getPublicIp(),getRtpBindIp()) : make_pair(getPublicIp(true),getRtpBindIp(true));
}

Agent::Network::Network(const Network &net): mIP(net.mIP) {
	memcpy(&mNetwork, &net.mNetwork, sizeof(mNetwork));
}

Agent::Network::Network(const struct ifaddrs *ifaddr) {
	int err = 0;
	char ipAddress[IPADDR_SIZE];
	memset(&mNetwork, 0, sizeof(mNetwork));
	if (ifaddr->ifa_addr->sa_family == AF_INET) {
		struct sockaddr_in *network = (struct sockaddr_in *) &mNetwork;
		struct sockaddr_in *if_addr = (struct sockaddr_in *) ifaddr->ifa_addr;
		struct sockaddr_in *if_mask = (struct sockaddr_in *) ifaddr->ifa_netmask;
		mNetwork.ss_family = AF_INET;
		network->sin_addr.s_addr = if_addr->sin_addr.s_addr & if_mask->sin_addr.s_addr;
		err = getnameinfo(ifaddr->ifa_addr, sizeof(struct sockaddr_in), ipAddress, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	} else if (ifaddr->ifa_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *network = (struct sockaddr_in6 *) &mNetwork;
		struct sockaddr_in6 *if_addr = (struct sockaddr_in6 *) ifaddr->ifa_addr;
		struct sockaddr_in6 *if_mask = (struct sockaddr_in6 *) ifaddr->ifa_netmask;
		for (int i = 0; i < 4; ++i) {
			network->sin6_addr.s6_addr[i] = if_addr->sin6_addr.s6_addr[i] & if_mask->sin6_addr.s6_addr[i];
		}
		mNetwork.ss_family = AF_INET6;
		err = getnameinfo(ifaddr->ifa_addr, sizeof(struct sockaddr_in6), ipAddress, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	}
	if (err == 0) {
		mIP = string(ipAddress);
	} else {
		LOGE("getnameinfo error: %s", strerror(errno));
	}

}

const string Agent::Network::getIP() const {
	return mIP;
}

bool Agent::Network::isInNetwork(const struct sockaddr *addr) const {
	if (addr->sa_family != mNetwork.ss_family) {
		return false;
	}
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *network = (struct sockaddr_in *) &mNetwork;
		struct sockaddr_in *if_addr = (struct sockaddr_in *) addr;
		return (network->sin_addr.s_addr & if_addr->sin_addr.s_addr) == network->sin_addr.s_addr;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *network = (struct sockaddr_in6 *) &mNetwork;
		struct sockaddr_in6 *if_addr = (struct sockaddr_in6 *) addr;
		for (int i = 0; i < 4; ++i) {
			if ((network->sin6_addr.s6_addr[i] & if_addr->sin6_addr.s6_addr[i]) != network->sin6_addr.s6_addr[i])
				return false;
		}
	}
	return true;
}

string Agent::Network::print(const struct ifaddrs *ifaddr) {
	stringstream ss;
	int err;
	int size = (ifaddr->ifa_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	char result[IPADDR_SIZE];
	ss << "Name: " << ifaddr->ifa_name;

	err = getnameinfo(ifaddr->ifa_addr, size, result, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	if (err != 0) {
		ss << "\tAddress: " << "(Error)";
	} else {
		ss << "\tAddress: " << result;
	}
	err = getnameinfo(ifaddr->ifa_netmask, size, result, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	if (err != 0) {
		ss << "\tMask: " << "(Error)";
	} else {
		ss << "\tMask: " << result;
	}

	return ss.str();
}

int Agent::countUsInVia(sip_via_t *via) const {
	int count = 0;
	for (sip_via_t *v = via; v != NULL; v = v->v_next) {
		if (isUs(v->v_host, v->v_port, true))
			++count;
	}

	return count;
}

bool Agent::isUs(const char *host, const char *port, bool check_aliases) const {
	char *tmp = NULL;
	int end;
	tport_t *tport=tport_primaries(nta_agent_tports(mAgent));
	
	//skip possibly trailing '.' at the end of host
	if (host[end = (strlen(host) - 1)] == '.') {
		tmp = (char*) alloca(end+1);
		memcpy(tmp, host, end);
		tmp[end] = '\0';
		host = tmp;
	}
	const char *matched_port=port;
	for(;tport!=NULL;tport=tport_next(tport)){
		const tp_name_t *tn=tport_name(tport);
		if (port==NULL){
			if (strcmp(tn->tpn_proto,"tls")==0)
				matched_port="5061";
			else matched_port="5060";
		}
		if (strcmp(matched_port,tn->tpn_port)==0){
			if (strcmp(host,tn->tpn_canon)==0)
				return true;
			if (check_aliases) {
				list<string>::const_iterator it;
				for (it = mAliases.begin(); it != mAliases.end(); ++it) {
					if (strcasecmp(host, (*it).c_str()) == 0)
						return true;
				}
			}
		}
	}
	return false;
}

sip_via_t *Agent::getNextVia(sip_t *response) {
	sip_via_t *via;
	for (via = response->sip_via; via != NULL; via = via->v_next) {
		if (!isUs(via->v_host, via->v_port, FALSE))
			return via;
	}
	return NULL;
}

/**
 * Takes care of an eventual maddr parameter.
 */
bool Agent::isUs(const url_t *url, bool check_aliases) const {
	char maddr[50];
	if (url_param(url->url_params, "maddr", maddr, sizeof(maddr))) {
		return isUs(maddr, url->url_port, check_aliases);
	} else {
		return isUs(url->url_host, url->url_port, check_aliases);
	}
}

void Agent::logEvent(const shared_ptr<SipEvent> &ev){
	if (mLogWriter){
		shared_ptr<EventLog> evlog;
		if ((evlog=ev->getEventLog<EventLog>())){
			if (evlog->isCompleted()) mLogWriter->write(evlog);
		}
	}
}

struct ModuleHasName {
	ModuleHasName(const string &ref) :
	match(ref) {
	}
	bool operator()(Module *module) {
		return module->getModuleName() == match;
	}
	const string &match;
};
Module *Agent::findModule(const string &modname) const {
	auto it=find_if(mModules.begin(), mModules.end(), ModuleHasName(modname));
	return (it != mModules.end()) ? *it : NULL;
}

template <typename SipEventT>
inline void Agent::doSendEvent
(shared_ptr<SipEventT> ev, const list<Module *>::iterator &begin, const list<Module *>::iterator &end) {
	#define LOG_SCOPED_EV_THREAD(ssargs, key) LOG_SCOPED_THREAD(key, ssargs->getOrEmpty(key));
	
	auto ssargs=ev->getMsgSip()->getSipAttr();
	LOG_SCOPED_EV_THREAD(ssargs, "from.uri.user");
	LOG_SCOPED_EV_THREAD(ssargs, "from.uri.domain");
	LOG_SCOPED_EV_THREAD(ssargs, "to.uri.user");
	LOG_SCOPED_EV_THREAD(ssargs, "to.uri.domain");
	LOG_SCOPED_EV_THREAD(ssargs, "method_or_status");
	LOG_SCOPED_EV_THREAD(ssargs, "callid");
	

	for (auto it = begin; it != end; ++it) {
		ev->mCurrModule = (*it);
		(*it)->process(ev);
		if (ev->isTerminated() || ev->isSuspended())
			break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		LOGA("Event not handled");
	}	
}


void Agent::sendRequestEvent(shared_ptr<RequestSipEvent> ev) {
	sip_t *sip=ev->getMsgSip()->mSip;
	const sip_request_t *req=sip->sip_request;
	const url_t *from= sip->sip_from->a_url;
	SLOGD << "Receiving new Request SIP message "
		<< req->rq_method_name
		<< " from " << from->url_user << "@" << from->url_host << " :"
		<< "\n" << *ev->getMsgSip();
	switch (req->rq_method) {
	case sip_method_register:
		++*mCountIncomingRegister;
		break;
	case sip_method_invite:
		++*mCountIncomingInvite;
		break;
	case sip_method_ack:
		++*mCountIncomingAck;
		break;
	case sip_method_info:
		++*mCountIncomingInfo;
		break;
	case sip_method_cancel:
		++*mCountIncomingCancel;
		break;
	case sip_method_bye:
		++*mCountIncomingBye;
		break;
	case sip_method_message:
		++*mCountIncomingMessage;
		break;
	case sip_method_options:
		++*mCountIncomingOptions;
		break;
	default:
		if (strcmp(req->rq_method_name, "DECLINE")==0) {
			++*mCountIncomingDecline;
		} else {
			++*mCountIncomingReqUnknown;
		}
		break;
	}

	doSendEvent(ev, mModules.begin(), mModules.end());
}

void Agent::sendResponseEvent(shared_ptr<ResponseSipEvent> ev) {
	SLOGD << "Receiving new Response SIP message: "
	<< ev->getMsgSip()->mSip->sip_status->st_status << "\n"
	<< *ev->getMsgSip();

	sip_t *sip=ev->getMsgSip()->mSip;
	switch (sip->sip_status->st_status) {
	case 100:
		++*mCountIncoming100;
		break;
	case 101:
		++*mCountIncoming101;
		break;
	case 180:
		++*mCountIncoming180;
		break;
	case 200:
		++*mCountIncoming200;
		break;
	case 202:
		++*mCountIncoming202;
		break;
	case 401:
		++*mCountIncoming401;
		break;
	case 404:
		++*mCountIncoming404;
		break;
	case 407:
		++*mCountIncoming407;
		break;
	case 408:
		++*mCountIncoming408;
		break;
	case 486:
		++*mCountIncoming486;
		break;
	case 487:
		++*mCountIncoming487;
		break;
	case 488:
		++*mCountIncoming488;
		break;
	case 603:
		++*mCountIncoming603;
		break;
	default:
		++*mCountIncomingResUnknown;
		break;
	}

	doSendEvent(ev, mModules.begin(), mModules.end());
}

void Agent::injectRequestEvent(shared_ptr<RequestSipEvent> ev) {
	SLOGD << "Inject Request SIP message:\n" << *ev->getMsgSip();
	ev->restartProcessing();
	SLOGD << "Injecting request event after " << ev->mCurrModule->getModuleName();
	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		if (ev->mCurrModule == *it) {
			++it;
			break;
		}
	}

	doSendEvent(ev, it, mModules.end());
}

void Agent::injectResponseEvent(shared_ptr<ResponseSipEvent> ev) {
	SLOGD << "Inject Response SIP message:\n" << *ev->getMsgSip();
	list<Module*>::iterator it;
	ev->restartProcessing();
	SLOGD << "Injecting response event after " << ev->mCurrModule->getModuleName();
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		if (ev->mCurrModule == *it) {
			++it;
			break;
		}
	}

	doSendEvent(ev, it, mModules.end());
}

void Agent::sendTransactionEvent(shared_ptr<TransactionEvent> ev) {
	SLOGD << "Propagating new Transaction Event " << ev->transaction.get()
			<< " " << ev->getKindName();
	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		(*it)->processTransactionEvent(ev);
	}
}

/**
 * This is a dangerous function when called at the wrong time.
 * So we prefer an early abort with a stack trace.
 * Indeed, incoming tport is global in sofia and will be overwritten
 */
static std::shared_ptr<tport_t> getIncomingTport(const msg_t *orig, Agent *ag) {
	tport_t *primaries=nta_agent_tports(ag->getSofiaAgent());
	tport_t *tport=tport_delivered_by(primaries,orig);
	if (!tport) LOGA("tport not found");
	return shared_ptr<tport_t>(tport_ref(tport), tport_unref);
}


int Agent::onIncomingMessage(msg_t *msg, const sip_t *sip) {
	if (mTerminating) {
		// Avoid throwing a bad weak pointer on GatewayAdapter destruction
		LOGI("Skipping incoming message on expired agent");
		return -1;
	}
	// Assuming sip is derived from msg
	shared_ptr<MsgSip> ms(new MsgSip(msg));
	if (sip->sip_request) {
		auto inTport=getIncomingTport(msg, this);
		auto ev = make_shared<RequestSipEvent>(shared_from_this(), ms, inTport);
		sendRequestEvent(ev);
	} else {
		auto ev = make_shared<ResponseSipEvent>(shared_from_this(), ms);
		sendResponseEvent(ev);
	}
	msg_destroy(msg);
	return 0;
}

int Agent::messageCallback(nta_agent_magic_t *context, nta_agent_t *agent, msg_t *msg, sip_t *sip) {
	Agent *a = (Agent*) context;
	return a->onIncomingMessage(msg, sip);
}

void Agent::idle() {
	SLOGD << "In Agent::idle()";
	for_each(mModules.begin(), mModules.end(), mem_fun(&Module::idle));
	if (GenericManager::get()->mNeedRestart) {
		exit(RESTART_EXIT_CODE);
	}
}

const string& Agent::getUniqueId() const {
	return mUniqueId;
}

su_timer_t *Agent::createTimer(int milliseconds, timerCallback cb, void *data) {
	su_timer_t *timer = su_timer_create(su_root_task(mRoot), milliseconds);
	su_timer_set_for_ever(timer, (su_timer_f) cb, data);
	return timer;
}

void Agent::stopTimer(su_timer_t *t) {
	su_timer_destroy(t);
}

void Agent::send(const shared_ptr<MsgSip> &ms, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	msg_t* msg = msg_dup(ms->getMsg());
	nta_msg_tsend(mAgent, msg, u, ta_tags(ta),TAG_END());
	ta_end(ta);
}

void Agent::incrReplyStat(int status) {
	switch (status) {
	case 100:
		++*mCountReply100;
		break;
	case 101:
		++*mCountReply101;
		break;
	case 180:
		++*mCountReply180;
		break;
	case 200:
		++*mCountReply200;
		break;
	case 202:
		++*mCountReply202;
		break;
	case 401:
		++*mCountReply401;
		break;
	case 404:
		++*mCountReply404;
		break;
	case 407:
		++*mCountReply407;
		break;
	case 408:
		++*mCountReply408;
		break;
	case 486:
		++*mCountReply486;
		break;
	case 487:
		++*mCountReply487;
		break;
	case 488:
		++*mCountReply488;
		break;
	default:
		++*mCountReplyResUnknown;
		break;
	}
}
void Agent::reply(const shared_ptr<MsgSip> &ms, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	incrReplyStat(status);
	ta_list ta;
	ta_start(ta, tag, value);
	msg_t* msg = ms->createOrigMsgRef();
	nta_msg_treply(mAgent, msg, status, phrase, ta_tags(ta));
	ta_end(ta);
}

