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

#if 0
static bool resolveAddress(const string &address, string &ipAddress) {
	int err;
	char buff[IPADDR_SIZE];
	struct addrinfo addr;
	memset(&addr, 0, sizeof(addr));
	addr.ai_family = PF_INET;
	struct addrinfo *result;
	err = getaddrinfo(address.c_str(), NULL, &addr, &result);
	if (err == 0) {
		err = getnameinfo(result->ai_addr, result->ai_addrlen, buff, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
		freeaddrinfo(result);
		if (err == 0) {
			ipAddress.assign(buff);
			return true;
		} else {
			LOGE("getnameinfo error: %s", strerror(errno));
		}
	} else {
		LOGE("getaddrinfo error: %s", strerror(errno));
	}
	return false;
}

static bool isIPAddress(const string &address) {
	int err;
	struct addrinfo addr;
	memset(&addr, 0, sizeof(addr));
	addr.ai_family = AF_UNSPEC;
	addr.ai_flags = AI_NUMERICHOST;

	struct addrinfo *result;
	err = getaddrinfo(address.c_str(), NULL, &addr, &result);
	if (err == 0) {
		freeaddrinfo(result);
		return true;
	} else {
		LOGE("getaddrinfo error: %s", strerror(errno));
	}
	return false;
}

static int get_local_ip_for_with_connect(int type, const char *dest, char *result) {
	int err, tmp;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct sockaddr_storage addr;
	int sock;
	socklen_t s;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = (type == AF_INET6) ? PF_INET6 : PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	/*hints.ai_flags=AI_NUMERICHOST|AI_CANONNAME;*/
	err = getaddrinfo(dest, "5060", &hints, &res);
	if (err != 0) {
		LOGE("getaddrinfo() error: %s", strerror(err));
		return -1;
	}
	if (res == NULL) {
		LOGE("bug: getaddrinfo returned nothing.");
		return -1;
	}
	sock = socket(res->ai_family, SOCK_DGRAM, 0);
	tmp = 1;
	err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(int));
	if (err < 0) {
		LOGW("Error in setsockopt: %s", strerror(errno));
	}
	err = connect(sock, res->ai_addr, res->ai_addrlen);
	if (err < 0) {
		LOGE("Error in connect: %s", strerror(errno));
		freeaddrinfo(res);
		close(sock);
		return -1;
	}
	freeaddrinfo(res);
	res = NULL;
	s = sizeof(addr);
	err = getsockname(sock, (struct sockaddr*) &addr, &s);
	if (err != 0) {
		LOGE("Error in getsockname: %s", strerror(errno));
		close(sock);
		return -1;
	}

	err = getnameinfo((struct sockaddr *) &addr, s, result, IPADDR_SIZE, NULL, 0, NI_NUMERICHOST);
	if (err != 0) {
		LOGE("getnameinfo error: %s", strerror(errno));
	}
	close(sock);
	return 0;
}

#endif

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
}


void Agent::start(const char *transport_override){
	GenericStruct *cr=GenericManager::get()->getRoot();
	list<string> transports=cr->get<GenericStruct>("global")->get<ConfigStringList>("transports")->read();
	
	if (transport_override){
		transports=ConfigStringList::parse(transport_override);
	}

#if 0
	if (mPublicAddress.empty() || mPublicAddress == "guess") {
		char localip[128];
		get_local_ip_for_with_connect(AF_INET, "209.85.229.147", localip);
		mPublicAddress = localip;
	}
#endif
	
	for(auto it=transports.begin();it!=transports.end();++it){
		const string &uri=(*it);
		char bindIp[128];
		url_t *url;
		int err;
		su_home_t home;
		su_home_init(&home);
		url=url_make(&home,uri.c_str());
		LOGD("Enabling transport %s",uri.c_str());
		if (mBindIp.empty()){
			if (url_param(url->url_params,"maddr",bindIp,sizeof(bindIp))>0){
				mBindIp=bindIp;
			}
		}
		if (uri.find("sips")==0){
			string keys = cr->get<GenericStruct>("global")->get<ConfigString>("tls-certificates-dir")->read();
			err=nta_agent_add_tport(mAgent,(const url_string_t*)url,TPTAG_CERTIFICATE(keys.c_str()), NTATAG_TLS_RPORT(1), TAG_END());
		}else{
			err=nta_agent_add_tport(mAgent,(const url_string_t*)url,NTATAG_CLIENT_RPORT(1), TAG_END());
		}
		if (err==-1){
			LOGE("Could not enable transport %s: %s",uri.c_str(),strerror(errno));
		}
		su_home_deinit(&home);
	}
	if (mBindIp.empty())
		mBindIp="0.0.0.0";
	
	tport_t *primaries=tport_primaries(nta_agent_tports(mAgent));
	if (primaries==NULL) LOGA("No sip transport defined.");
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
	}
	
	char digest[(SU_MD5_DIGEST_SIZE*2)+1];
	su_md5_hexdigest(&ctx,digest);
	su_md5_deinit(&ctx);
	digest[16]='\0';//keep half of the digest, should be enough
	// compute a network wide unique id
	mUniqueId = digest;
	
	sip_contact_t *ctts=nta_agent_contact(mAgent);
	char prefUrl[266];
	url_e(prefUrl,sizeof(prefUrl),ctts->m_url);
	mPreferredRoute=ctts->m_url;
	LOGD("Preferred route is %s", prefUrl);
	
	mPublicIp=ctts->m_url->url_host;
	LOGD("Agent public ip is %s", mPublicIp.c_str());
}

Agent::Agent(su_root_t* root){
	GenericStruct *cr = GenericManager::get()->getRoot();
	
	EtcHostsResolver::get();

	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "NatHelper"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Authentication"));
#ifdef HAVE_DATEHANDLER
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "DateHandler"));
#endif
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "GatewayAdapter"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Registrar"));
#ifdef ENABLE_PUSHNOTIFICATION
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "PushNotification"));
#endif
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "ContactRouteInserter"));
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
}

Agent::~Agent() {
	for_each(mModules.begin(), mModules.end(), delete_functor<Module>());
	if (mAgent)
		nta_agent_destroy(mAgent);
}

const char *Agent::getServerString() const {
	return mServerString.c_str();
}

std::string Agent::getPreferredRoute()const{
	char prefUrl[266];
	url_e(prefUrl,sizeof(prefUrl),mPreferredRoute);
	return string(prefUrl);
}

void Agent::loadConfig(GenericManager *cm) {
	cm->loadStrict(); //now that each module has declared its settings, we need to reload from the config file
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


std::string Agent::getPreferredIp(const std::string &destination) const {
	int err;
	struct addrinfo addr;
	memset(&addr, 0, sizeof(addr));
	addr.ai_family = PF_INET;
	addr.ai_flags = AI_NUMERICHOST;

	struct addrinfo *result;
	err = getaddrinfo(destination.c_str(), NULL, &addr, &result);
	if (err == 0) {
		for (auto it = mNetworks.begin(); it != mNetworks.end(); ++it) {
			if (it->isInNetwork(result->ai_addr)) {
				freeaddrinfo(result);
				return it->getIP();
			}
		}

		freeaddrinfo(result);
	} else {
		LOGE("getaddrinfo error: %s", strerror(errno));
	}
	return getPublicIp();
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
			network->sin6_addr.s6_addr32[i] = if_addr->sin6_addr.s6_addr32[i] & if_mask->sin6_addr.s6_addr32[i];
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
			if ((network->sin6_addr.s6_addr32[i] & if_addr->sin6_addr.s6_addr32[i]) != network->sin6_addr.s6_addr32[i])
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

void Agent::sendRequestEvent(shared_ptr<RequestSipEvent> ev) {
	sip_t *sip=ev->getMsgSip()->mSip;
	sip_request_t *req=sip->sip_request;
	ev->getMsgSip()->log("Receiving new Request SIP message: %s",
			req->rq_method_name);
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


	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		ev->mCurrModule = (*it);
		(*it)->processRequest(ev);
		if (ev->isTerminated() || ev->isSuspended())
			break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		LOGA("Event not handled");
	}
}

void Agent::sendResponseEvent(shared_ptr<ResponseSipEvent> ev) {
	ev->getMsgSip()->log("Receiving new Response SIP message: %d",
			ev->getMsgSip()->mSip->sip_status->st_status);

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

	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		ev->mCurrModule = *it;
		(*it)->processResponse(ev);
		if (ev->isTerminated() || ev->isSuspended())
			break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		LOGA("Event not handled");
	}
}

void Agent::injectRequestEvent(shared_ptr<RequestSipEvent> ev) {
	LOG_START
	ev->getMsgSip()->log("Inject Request SIP message:");
	list<Module*>::iterator it;
	ev->restartProcessing();
	LOGD("Injecting request event after %s", ev->mCurrModule->getModuleName().c_str());
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		if (ev->mCurrModule == *it) {
			++it;
			break;
		}
	}
	for (; it != mModules.end(); ++it) {
		ev->mCurrModule = *it;
		(*it)->processRequest(ev);
		if (ev->isTerminated() || ev->isSuspended())
			break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		LOGA("Event not handled");
	}
	LOG_END
}

void Agent::injectResponseEvent(shared_ptr<ResponseSipEvent> ev) {
	LOG_START
	ev->getMsgSip()->log("Inject Response SIP message:");
	list<Module*>::iterator it;
	ev->restartProcessing();
	LOGD("Injecting response event after %s", ev->mCurrModule->getModuleName().c_str());
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		if (ev->mCurrModule == *it) {
			++it;
			break;
		}
	}
	for (; it != mModules.end(); ++it) {
		ev->mCurrModule = *it;
		(*it)->processResponse(ev);
		if (ev->isTerminated() || ev->isSuspended())
			break;
	}
	if (!ev->isTerminated() && !ev->isSuspended()) {
		LOGA("Event not handled");
	}
	LOG_END
}

void Agent::sendTransactionEvent(const shared_ptr<Transaction> &transaction, Transaction::Event event) {
	LOG_START
	LOGD("Propagating new Transaction Event %p %s", transaction.get(),
			Transaction::eventStr(event));
	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		(*it)->processTransactionEvent(transaction, event);
	}
	LOG_END
}

int Agent::onIncomingMessage(msg_t *msg, sip_t *sip) {
	// Assuming sip is derived from msg
	shared_ptr<MsgSip> ms(new MsgSip(msg));
	if (sip->sip_request) {
		shared_ptr<RequestSipEvent> ev(new RequestSipEvent(dynamic_pointer_cast<IncomingAgent>(shared_from_this()), ms));
		sendRequestEvent(ev);
	} else {
		shared_ptr<ResponseSipEvent> ev(new ResponseSipEvent(dynamic_pointer_cast<OutgoingAgent>(shared_from_this()), ms));
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
	nta_msg_tsend(mAgent, msg, u, ta_tags(ta));
	ta_end(ta);
}

void Agent::send(const shared_ptr<MsgSip> &ms) {
	msg_t* msg = msg_dup(ms->getMsg());
	nta_msg_tsend(mAgent, msg, NULL, TAG_END());
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

