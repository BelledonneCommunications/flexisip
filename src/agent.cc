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

#ifdef HAVE_CONFIG_H
#include "flexisip-config.h"
#endif
#include "agent.hh"
#include "module.hh"

#include "etchosts.hh"
#include <algorithm>
#include <sstream>
#include <sofia-sip/tport_tag.h>
#include <sofia-sip/su_tagarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <net/if.h>
#include <ifaddrs.h>

#define IPADDR_SIZE 64

using namespace ::std;

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
		LOGE("getaddrinfo() error: %s", gai_strerror(err));
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

Agent::Agent(su_root_t* root, int port, int tlsport) :
		mPort(port), mTlsPort(tlsport) {
	char sipuri[128] = { 0 };
	ConfigStruct *cr = ConfigManager::get()->getRoot();
	ConfigStruct *tls = cr->get<ConfigStruct>("tls");

	EtcHostsResolver::get();
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "NatHelper"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Authentication"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "GatewayAdapter"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Registrar"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "ContactRouteInserter"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "LoadBalancer"));
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "MediaRelay"));
#ifdef ENABLE_TRANSCODER
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this,"Transcoder"));
#endif
	mModules.push_back(ModuleFactory::get()->createModuleInstance(this, "Forward"));

	mServerString = "Flexisip/"
	VERSION
	" (sofia-sip-nta/" NTA_VERSION ")";

	for_each(mModules.begin(), mModules.end(), bind2nd(mem_fun(&Module::declare), cr));

	/* we pass "" as localaddr when we just want to dump the default config. So don't go further*/
	if (mPort == 0)
		return;

	if (mPort == -1)
		mPort = cr->get<ConfigStruct>("global")->get<ConfigInt>("port")->read();
	if (mTlsPort == -1)
		mTlsPort = tls->get<ConfigInt>("port")->read();

	string bind_address = cr->get<ConfigStruct>("global")->get<ConfigString>("bind-address")->read();
	mPublicIp = cr->get<ConfigStruct>("global")->get<ConfigString>("ip-address")->read();

	if (mPublicIp.empty() || mPublicIp == "guess") {
		char localip[128];
		get_local_ip_for_with_connect(AF_INET, "209.85.229.147", localip);
		mPublicIp = localip;
	}
	LOGI("Public IP address is %s, bind address is %s", mPublicIp.c_str(), bind_address.c_str());

	// compute a network wide unique id, REVISIT: compute a hash
	ostringstream oss;
	oss << mPublicIp << "_" << mPort;
	mUniqueId = oss.str();
	mRoot = root;

	snprintf(sipuri, sizeof(sipuri) - 1, "sip:%s:%i;maddr=%s", mPublicIp.c_str(), mPort, bind_address.c_str());
	LOGD("Enabling 'sip' listening point with uri '%s'.", sipuri);
	mAgent = nta_agent_create(root, (url_string_t*) sipuri, &Agent::messageCallback, (nta_agent_magic_t*) this, NTATAG_CLIENT_RPORT(1), NTATAG_UDP_MTU(1460), TAG_END());
	if (mAgent == NULL) {
		LOGF("Could not create sofia mta, certainly SIP ports already in use.");
	}
	if (tls->get<ConfigBoolean>("enabled")->read()) {
		string keys = tls->get<ConfigString>("certificates-dir")->read();
		snprintf(sipuri, sizeof(sipuri) - 1, "sips:%s:%i;maddr=%s", mPublicIp.c_str(), mTlsPort, bind_address.c_str());
		LOGD("Enabling 'sips' listening point with uri '%s', keys in %s", sipuri, keys.c_str());
		nta_agent_add_tport(mAgent, (url_string_t*) sipuri, TPTAG_CERTIFICATE(keys.c_str()), NTATAG_CLIENT_RPORT(1), NTATAG_UDP_MTU(1460), NTATAG_TLS_RPORT(1), TAG_END());
	}

	if (bind_address == "*") {
		bind_address = "0.0.0.0";
	}
	mBindIp = bind_address;

	oss.str(mPreferredRoute);
	oss << "sip:";
	if (!mBindIp.empty() && mBindIp != "0.0.0.0" && mBindIp != "::0") {
		oss << mBindIp;
	} else {
		oss << mPublicIp;
	}
	oss << ":" << mPort;
	mPreferredRoute = oss.str();
	LOGD("Preferred route is %s", mPreferredRoute.c_str());
}

Agent::~Agent() {
	for_each(mModules.begin(), mModules.end(), delete_functor<Module>());
	if (mAgent)
		nta_agent_destroy(mAgent);
}

const char *Agent::getServerString() const {
	return mServerString.c_str();
}

void Agent::loadConfig(ConfigManager *cm) {
	cm->loadStrict(); //now that each module has declared its settings, we need to reload from the config file
	mAliases = cm->getGlobal()->get<ConfigStringList>("aliases")->read();
	discoverInterfaces();
	LOGD("List of host aliases:");
	for (list<string>::iterator it = mAliases.begin(); it != mAliases.end(); ++it) {
		LOGD("%s", (*it).c_str());
	}
	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it)
		(*it)->load(this);
}

void Agent::setDomain(const string &domain) {
	mDomain = domain;
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
	int p = (port != NULL) ? atoi(port) : 5060;
	if (p != mPort && p != mTlsPort)
		return false;
	//skip possibly trailing '.' at the end of host
	if (host[end = (strlen(host) - 1)] == '.') {
		tmp = (char*) alloca(end+1);
		memcpy(tmp, host, end);
		tmp[end] = '\0';
		host = tmp;
	}
	if (strcmp(host, mPublicIp.c_str()) == 0)
		return true;
	if (check_aliases) {
		list<string>::const_iterator it;
		for (it = mAliases.begin(); it != mAliases.end(); ++it) {
			if (strcasecmp(host, (*it).c_str()) == 0)
				return true;
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

bool Agent::isUs(const url_t *url, bool check_aliases) const {
	return isUs(url->url_host, url->url_port, check_aliases);
}

void Agent::sendRequestEvent(shared_ptr<SipEvent> &ev) {
	ev->getMsgSip()->log("Receiving new Request SIP message:");
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

void Agent::sendResponseEvent(shared_ptr<SipEvent> &ev) {
	ev->getMsgSip()->log("Receiving new Response SIP message:");
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

void Agent::injectRequestEvent(shared_ptr<SipEvent> &ev) {
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
}

void Agent::injectResponseEvent(shared_ptr<SipEvent> &ev) {
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
}

void Agent::sendTransactionEvent(const std::shared_ptr<Transaction> &transaction, Transaction::Event event) {
	LOGD("Receiving new Transaction Event %p %i", transaction.get(), event);
	list<Module*>::iterator it;
	for (it = mModules.begin(); it != mModules.end(); ++it) {
		(*it)->processTransactionEvent(transaction, event);
	}
}

int Agent::onIncomingMessage(msg_t *msg, sip_t *sip) {
	shared_ptr<MsgSip> ms(make_shared<MsgSip>(msg, sip));
	msg_destroy(msg);
	if (sip->sip_request) {
		shared_ptr<SipEvent> ev(new RequestSipEvent(shared_from_this(), ms));
		sendRequestEvent(ev);
	}
	else {
		shared_ptr<SipEvent> ev(new ResponseSipEvent(shared_from_this(), ms));
		sendResponseEvent(ev);
	}
	return 0;
}

int Agent::messageCallback(nta_agent_magic_t *context, nta_agent_t *agent, msg_t *msg, sip_t *sip) {
	Agent *a = (Agent*) context;
	return a->onIncomingMessage(msg, sip);
}

void Agent::idle() {
	for_each(mModules.begin(), mModules.end(), mem_fun(&Module::idle));
}

const string& Agent::getUniqueId() const {
	return mUniqueId;
}

su_timer_t *Agent::createTimer(int milliseconds, timerCallback cb, void *data) {
	su_timer_t *timer = su_timer_create(su_root_task(mRoot), milliseconds);
	su_timer_run(timer, (su_timer_f) cb, data);
	return timer;
}

void Agent::stopTimer(su_timer_t *t) {
	su_timer_destroy(t);
}

void Agent::discoverInterfaces() {
	struct ifaddrs *ifp;
	struct ifaddrs *ifpstart;
	char address[NI_MAXHOST];

	if (getifaddrs(&ifpstart) < 0) {
		return;
	}

	for (ifp = ifpstart; ifp != NULL; ifp = ifp->ifa_next) {
		if (ifp->ifa_addr && (ifp->ifa_flags & IFF_RUNNING)) {
			if (getnameinfo(ifp->ifa_addr, sizeof(sockaddr_storage), address, sizeof(address), NULL, 0, NI_NUMERICHOST) == 0) {
				if (strchr(address, '%') == NULL) { /*avoid ipv6 link-local addresses */
					mAliases.push_back(string(address));
				}
			}
		}
	}
	freeifaddrs(ifpstart);
}

void Agent::send(const std::shared_ptr<MsgSip> &ms, url_string_t const *u, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	msg_t* msg = msg_dup(ms->getMsg());
	nta_msg_tsend(mAgent, msg, u, ta_tags(ta));
	ta_end(ta);
}

void Agent::send(const std::shared_ptr<MsgSip> &ms) {
	msg_t* msg = msg_dup(ms->getMsg());
	nta_msg_tsend(mAgent, msg, NULL, TAG_END());
}

void Agent::reply(const std::shared_ptr<MsgSip> &ms, int status, char const *phrase, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;
	ta_start(ta, tag, value);
	msg_t* msg = msg_dup(ms->getMsg());
	nta_msg_treply(mAgent, msg, status, phrase, ta_tags(ta));
	ta_end(ta);
}

