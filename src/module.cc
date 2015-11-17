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

#include "module.hh"
#include "agent.hh"
#include "entryfilter.hh"
#include "sofia-sip/auth_digest.h"
#include "sofia-sip/nta.h"
#include "log/logmanager.hh"

#include "expressionparser.hh"

#include <algorithm>
using namespace::std;

list<string> Module::sPushNotifParams {
	"pn-tok", "pn-type", "app-id", "pn-msg-str", "pn-call-str", "pn-call-snd", "pn-msg-snd"
};

ModuleInfoBase::~ModuleInfoBase() {}

Module *ModuleInfoBase::create(Agent *ag){
	Module *mod=_create(ag);
	mod->setInfo(this);
	return mod;
}

ModuleFactory * ModuleFactory::sInstance = NULL;

ModuleFactory *ModuleFactory::get() {
	if (sInstance == NULL) {
		sInstance = new ModuleFactory();
	}
	return sInstance;
}

struct hasName {
	hasName(const string &ref) :
			match(ref) {
	}
	bool operator()(ModuleInfoBase *info) {
		return info->getModuleName() == match;
	}
	const string &match;
};

Module *ModuleFactory::createModuleInstance(Agent *ag, const string &modname) {
	list<ModuleInfoBase*>::iterator it;
	it = find_if(mModules.begin(), mModules.end(), hasName(modname));
	if (it != mModules.end()) {
		Module *m;
		ModuleInfoBase *i = *it;
		m = i->create(ag);
		LOGI("Creating module instance for [%s]", m->getModuleName().c_str());
		return m;
	}
	LOGA("Could not find any registered module with name [%s]",modname.c_str());
	return NULL;
}

void ModuleFactory::registerModule(ModuleInfoBase *m) {
	//LOGI("Registering module %s", m->getModuleName().c_str());
	//Disabled as called from static intitialization...
	mModules.push_back(m);
}

Module::Module(Agent *ag) :
		mAgent(ag) {
	su_home_init(&mHome);
	mFilter = new ConfigEntryFilter();
}

bool Module::isEnabled() const {
	return mFilter->isEnabled();
}


Module::~Module() {
	delete mFilter;
	su_home_deinit(&mHome);
}

bool Module::doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) {
	LOGD("Configuration of module %s changed for key %s to %s", mInfo->getModuleName().c_str(),
			conf.getName().c_str(), conf.get().c_str());
	switch (state) {
		case ConfigState::Check:
			return isValidNextConfig(conf);
		case ConfigState::Changed:
			mDirtyConfig=true;
			break;
		case ConfigState::Reset:
			mDirtyConfig=false;
			break;
		case ConfigState::Commited:
			if (mDirtyConfig) {
				LOGI("Reloading config of module %s", mInfo->getModuleName().c_str());
				reload();
				mDirtyConfig=false;
			}
			break;
	}
	return true;
}

void Module::setInfo(ModuleInfoBase *i) {
	mInfo = i;
}

Agent *Module::getAgent() const {
	return mAgent;
}

nta_agent_t *Module::getSofiaAgent()const{
	return mAgent->mAgent;
}

void Module::declare(GenericStruct *root){
	mModuleConfig=new GenericStruct("module::"+getModuleName(),mInfo->getModuleHelp(),mInfo->getOidIndex());
	mModuleConfig->setConfigListener(this);
	root->addChild(mModuleConfig);
	mFilter->declareConfig(mModuleConfig);
	onDeclare(mModuleConfig);
}

void Module::checkConfig() {
	list<GenericEntry *> children=mModuleConfig->getChildren();
	for (auto it=children.begin(); it != children.end(); ++it) {
		const ConfigValue *cv=dynamic_cast<ConfigValue *>(*it);
		if (cv && !isValidNextConfig(*cv)) {
			LOGF("Invalid config %s:%s=%s",
					getModuleName().c_str(),
					cv->getName().c_str(),
					cv->get().c_str());
		}
	}
}

void Module::load() {
	mFilter->loadConfig(mModuleConfig);
	if (mFilter->isEnabled())
		onLoad(mModuleConfig);
}

void Module::reload() {
	onUnload();
	load();
}

void Module::processRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	LOG_SCOPED_THREAD("Module", getModuleName());
	try {
		if(mFilter->canEnter(ms)) {
			SLOGD << "Invoking onRequest() on module "<< getModuleName();
			onRequest(ev);
		} else {
			SLOGD <<"Skipping onRequest() on module "<< getModuleName();
		}
	} catch (FlexisipException &fe) {
		SLOGD << "Skipping onRequest() on module " << getModuleName() << " because "  << fe;
	} catch (...) {
		SLOGD << "Skipping onRequest() on module (error)" << getModuleName();
	}
}

void Module::processResponse(shared_ptr<ResponseSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	LOG_SCOPED_THREAD("Module", getModuleName());
	try {
		if(mFilter->canEnter(ms)) {
			LOGD("Invoking onResponse() on module %s", getModuleName().c_str());
			onResponse(ev);
		} else {
			LOGD("Skipping onResponse() on module %s", getModuleName().c_str());
		}
	} catch (FlexisipException &fe) {
		SLOGD <<"Skipping onResponse() on module" << getModuleName() << " because " << fe;
	} catch (...) {
		SLOGD << "Skipping onRequest() on module (error)" << getModuleName();
	}
}

void Module::idle() {
	if (mFilter->isEnabled()) {
		onIdle();
	}
}

const string &Module::getModuleName() const {
	return mInfo->getModuleName();
}

ModuleType_e Module::type() const {
	return mInfo->type();
}

msg_auth_t *ModuleToolbox::findAuthorizationForRealm(su_home_t *home, msg_auth_t *au, const char *realm) {
	while (au!= NULL) {
		auth_response_t r;
		memset(&r, 0, sizeof(r));
		r.ar_size=sizeof(r);
		auth_digest_response_get(home, &r, au->au_params);
		LOGD("Examining auth digest response %s %s", r.ar_username, r.ar_realm);
		if (strcasecmp(r.ar_realm, realm) ==0) {
			LOGD("Expected realm found : %s", r.ar_realm);
			return au;
		}
		au=au->au_next;
	}
	LOGD("authorization with expected realm '%s' not found", realm);
	return NULL;
}

bool ModuleToolbox::sipPortEquals(const char *p1, const char *p2, const char *transport){
	int n1,n2;
	if (transport==NULL || strcasecmp(transport,"TLS")==0)
		n1=n2=5060;
	else
		n1=n2=5061;

	if (p1 && p1[0]!='\0')
		n1=atoi(p1);
	if (p2 && p2[0]!='\0')
		n2=atoi(p2);
	return n1==n2;
}

int ModuleToolbox::sipPortToInt(const char *port){
	if (port==NULL || port[0]=='\0') return 5060;
	else return atoi(port);
}

void ModuleToolbox::cleanAndPrependRoute(Agent *ag, msg_t *msg, sip_t *sip, sip_route_t *r){
	// removes top route headers if they matches us
	while (sip->sip_route != NULL && ag->isUs(sip->sip_route->r_url)) {
		sip_route_remove(msg, sip);
	}
	if (r) prependNewRoutable(msg, sip, sip->sip_route, r);
}

url_t *ModuleToolbox::urlFromTportName(su_home_t *home, const tp_name_t *name){
	url_t *url=NULL;
	url_type_e ut=url_sip;

	if (strcasecmp(name->tpn_proto,"tls")==0){
		ut=url_sips;
	}
	url=(url_t*) su_alloc(home, sizeof(url_t));
	url_init(url, ut);

	if (strcasecmp(name->tpn_proto,"tcp")==0){
		url_param_add(home, url, "transport=tcp");
	}

	url->url_port=su_strdup(home, name->tpn_port);
	url->url_host=su_strdup(home, name->tpn_canon);

	return url;
}

void ModuleToolbox::addRecordRoute(su_home_t *home, Agent *ag, const shared_ptr<RequestSipEvent> &ev, const tport_t *tport){
	msg_t *msg=ev->getMsgSip()->getMsg();
	sip_t *sip=ev->getMsgSip()->getSip();
	url_t *url;

	if (tport){
		tport=tport_parent(tport); //get primary transport
		const tp_name_t *name=tport_name(tport); //primary transport name

		url=urlFromTportName(home,name);
		if (!url){
			LOGE("ModuleToolbox::addRecordRoute(): urlFromTportName() returned NULL");
			return;
		}
	}else{
		//default to Agent's default address.
		url=url_hdup(home,ag->getPreferredRouteUrl());
	}

	url_param_add(home,url,"lr");
	sip_record_route_t *rr=sip_record_route_create(home,url,NULL);
	if (!rr) {
		LOGE("ModuleToolbox::addRecordRoute(): sip_record_route_create() returned NULL");
		return;
	}

	if (!prependNewRoutable(msg, sip, sip->sip_record_route, rr)) {
		LOGD("Skipping addition of record route identical to top one");
		return;
	}

	LOGD("Record route added.");
	ev->mRecordRouteAdded=true;
}


void ModuleToolbox::addRecordRouteIncoming(su_home_t *home, Agent *ag, const shared_ptr<RequestSipEvent> &ev ) {
	if (ev->mRecordRouteAdded) return;

	auto tport=ev->getIncomingTport();
	if (!tport){
		LOGE("Cannot find incoming tport, cannot add a Record-Route.");
		return;
	}
	addRecordRoute(home,ag,ev,tport.get());
}

bool ModuleToolbox::fromMatch(const sip_from_t *from1, const sip_from_t *from2) {
	if (url_cmp(from1->a_url, from2->a_url) == 0) {
		if (from1->a_tag && from2->a_tag && strcmp(from1->a_tag, from2->a_tag) == 0)
			return true;
		if (from1->a_tag == NULL && from2->a_tag == NULL)
			return true;
	}
	return false;
}

bool ModuleToolbox::matchesOneOf(const char *item, const list<string> &set) {
	list<string>::const_iterator it;
	for (it = set.begin(); it != set.end(); ++it) {
		const char *tmp = (*it).c_str();
		if (tmp[0] == '*') {
			/*the wildcard matches everything*/
			return true;
		} else {
			if (strcmp(item, tmp) == 0)
				return true;
		}
	}
	return false;
}

bool ModuleToolbox::fixAuthChallengeForSDP(su_home_t *home, msg_t *msg, sip_t *sip) {
	sip_auth_t *auth;
	msg_param_t *par;
	auth = sip->sip_www_authenticate;
	if (auth == NULL)
		auth = sip->sip_proxy_authenticate;
	if (auth == NULL)
		return true;
	if (auth->au_params == NULL)
		return true;
	par = msg_params_find_slot((msg_param_t*) auth->au_params, "qop");
	if (par != NULL) {
		if (strstr(*par, "auth-int")) {
			LOGD("Authentication header has qop with 'auth-int', replacing by 'auth'");
			//if the qop contains "auth-int", replace it by "auth" so that it allows to modify the SDP
			*par = su_strdup(home, "qop=\"auth\"");
		}
	}
	return true;
}

void ModuleToolbox::urlSetHost(su_home_t *home, url_t *url, const char *host){
	if (strchr(host,':') && host[0]!='['){
		url->url_host=su_sprintf(home, "[%s]", host);
	}else url->url_host=su_strdup(home, host);
}

string ModuleToolbox::getHost(const char *host){
	if (host[0]=='['){
		return string(host, 1, strlen(host)-2);
	}
	return string(host);
}

string ModuleToolbox::urlGetHost(url_t *url){
	return getHost(url->url_host);
}

bool ModuleToolbox::urlHostMatch(const char *host1, const char *host2){
	size_t len1,len2;
	int ipv6=0;
	len1=strlen(host1);
	if (host1[0]=='['){
		host1++;
		len1-=2;
		ipv6++;
	}else if (strchr(host1,':')) ipv6++;
	len2=strlen(host2);
	if (host2[0]=='['){
		host2++;
		len2-=2;
		ipv6++;
	}else if (strchr(host2,':')) ipv6++;
	if (ipv6==2){
		/*since there exist multiple text representations of ipv6 addresses, it is necessary to switch to binary representation to make the comparision*/
		string ip1(host1,len1), ip2(host2, len2);
		struct sockaddr_in6 addr1={0}, addr2={0};
		if (inet_pton(AF_INET6, ip1.c_str(), &addr1)==1 && inet_pton(AF_INET6, ip2.c_str(), &addr2)==1){
			return memcmp(&addr1, &addr2, sizeof(addr1))==0;
		}else{
			LOGW("Comparing invalid IPv6 addresses %s | %s",host1, host2);
		}
	}
	return strncasecmp(host1,host2,MAX(len1,len2))==0;
}

bool ModuleToolbox::urlHostMatch(url_t *url, const char *host){
	return urlHostMatch(url->url_host, host);
}

bool ModuleToolbox::transportEquals(const char *tr1, const char *tr2) {
	if (tr1 == NULL || tr1[0] == 0)
		tr1 = "UDP";
	if (tr2 == NULL || tr2[0] == 0)
		tr2 = "UDP";
	return strcasecmp(tr1, tr2) == 0;
}

bool ModuleToolbox::urlViaMatch(const url_t *url, const sip_via_t *via, bool use_received_rport){
	const char *via_host=NULL;
	const char *via_port=NULL;
	const char *via_transport=sip_via_transport(via);
	const char *url_host=url->url_host;
	const char *url_pt=url_port(url); //this function never returns NULL
	char url_transport[8]="UDP";

	char maddr[50];
	if (url_param(url->url_params, "maddr", maddr, sizeof(maddr))) {
		url_host = maddr;
	}

	if (use_received_rport){
		via_host=via->v_received;
		via_port=via->v_rport;
	}
	if (via_host==NULL){
		via_host=via->v_host;
	}
	if (via_port==NULL){
		via_port=via->v_port;
	}
	if (via_port==NULL){
		if (strcasecmp(via_transport,"TLS")==0) via_port="5051";
		else via_port="5060";
	}
	url_param(url->url_params,"transport",url_transport,sizeof(url_transport));
	if (strcmp(url->url_scheme,"sips")==0) strncpy(url_transport,"TLS",sizeof(url_transport));

	return urlHostMatch(via_host,url_host) && strcmp(via_port,url_pt)==0;
}

bool ModuleToolbox::viaContainsUrl(const sip_via_t *vias, const url_t* url){
	const sip_via_t *via;
	for (via = vias; via != NULL; via = via->v_next){
		if (urlViaMatch(url, via, true)) return true;
	}
	return false;
}

static const char *get_transport_name_sip(const char *transport){
	if (transport == NULL || transport[0]=='\0') return "UDP";
	else if (strcasecmp(transport, "udp") == 0) return "UDP";
	else if (strcasecmp(transport, "tcp") == 0) return "TCP";
	else if (strcasecmp(transport, "tls") == 0) return "TLS";
	return "INVALID";
}

static const char *get_transport_name_sips(const char *transport){
	if (transport == NULL || transport[0]=='\0') return "TLS";
	else if (strcasecmp(transport, "udp") == 0) return "DTLS";
	else if (strcasecmp(transport, "tcp") == 0) return "TLS";
	else if (strcasecmp(transport, "tls") == 0) return "TLS"; /*should not happen but not so serious*/
	return "INVALID";
}

static const char * url_get_transport(const url_t *url){
	char transport[8]={0};
	const char *ret = "UDP";
	
	url_param(url->url_params,"transport",transport,sizeof(transport));
	switch(url->url_type){
		case url_sip:
			ret = get_transport_name_sip(transport);
		break;
		case url_sips:
			ret = get_transport_name_sips(transport);
		break;
		default:
			LOGE("url_get_transport(): invalid url kind %i",(int) url->url_type);
		break;
	}
	return ret;
}

string ModuleToolbox::urlGetTransport(const url_t *url){
	return url_get_transport(url);
}

bool ModuleToolbox::urlTransportMatch(const url_t *url1, const url_t *url2){
	if (strcasecmp(url_get_transport(url1), url_get_transport(url2)) != 0) return false;
	if (!urlHostMatch(url1->url_host, url2->url_host)) return false;
	if (strcmp(url_port(url1), url_port(url2)) != 0) return false;
	
	return true;
}

bool ModuleToolbox::isNumeric(const char *host){
	if (host[0]=='[') return true; //ipv6
	struct in_addr addr;
	return !!inet_aton(host,&addr); //inet_aton returns non zero if ipv4 address is valid.
}

bool ModuleToolbox::isManagedDomain(const Agent *agent, const list<string> &domains, const url_t *url) {
	bool check=ModuleToolbox::matchesOneOf(url->url_host, domains);
	if (check){
		//additional check: if the domain is an ip address that is not this proxy, then it is not considered as a managed domain for the registrar.
		//we need this to distinguish requests that needs registrar routing from already routed requests.
		if (ModuleToolbox::isNumeric(url->url_host) && !agent->isUs(url,true)){
			check=false;
		}
	}
	return check;
}

void ModuleToolbox::addRoutingParam(su_home_t *home, sip_contact_t *c, const string &routingParam, const char *domain) {
	ostringstream oss;
	oss << routingParam << "=" << domain;
	string routing_param(oss.str());
	while (c != NULL) {
		url_param_add(home, c->m_url, routing_param.c_str());
		c = c->m_next;
	}
}

sip_route_t *ModuleToolbox::prependNewRoutable(msg_t *msg, sip_t *sip, sip_route_t * &sipr, sip_route_t * value) {
	if (sipr == NULL) {
		sipr = value;
		return value;
	}

	/*make sure we are not already in*/
	if (sipr && url_cmp_all(sipr->r_url,value->r_url)==0)
		return NULL;

	value->r_next = sipr;
	msg_header_remove_all(msg, (msg_pub_t*) sip, (msg_header_t*) sipr);
	msg_header_insert(msg, (msg_pub_t*) sip, (msg_header_t*) value);
	sipr = value;
	return value;
}

void ModuleToolbox::addPathHeader(Agent *ag, const shared_ptr< RequestSipEvent >& ev, const tport_t* tport, const char *uniq) {
	su_home_t *home=ev->getMsgSip()->getHome();
	msg_t *msg=ev->getMsgSip()->getMsg();
	sip_t *sip=ev->getMsgSip()->getSip();
	url_t *url;

	if (tport){
		tport=tport_parent(tport); //get primary transport
		const tp_name_t *name=tport_name(tport); //primary transport name

		url = urlFromTportName(home,name);
		if (!url){
			LOGE("ModuleToolbox::addPathHeader(): urlFromTportName() returned NULL");
			return;
		}
	}else{
		//default to Agent's default address.
		url=url_hdup(home,ag->getPreferredRouteUrl());
	}
	if (uniq) {
		char *lParam = su_sprintf(home, "fs-proxy-id=%s",uniq);
		url_param_add(home,url,lParam);
	}
	url_param_add(home, url, "lr");
	sip_path_t *path = (sip_path_t*)su_alloc(home,sizeof(sip_path_t));
	sip_path_init(path);
	
	path->r_url[0] = *url;

	if (!prependNewRoutable(msg, sip, sip->sip_path, path)) {
		SLOGD << "Identical path already existing: " << url_as_string(home, url);
	} else {
		SLOGD << "Path added to: " << url_as_string(home, url);
	}
}

void ModuleToolbox::removeParamsFromContacts(su_home_t *home, sip_contact_t *c, list<string> &params) {
	while (c) {
		removeParamsFromUrl(home, c->m_url, params);
		c=c->m_next;
	}
}

void ModuleToolbox::removeParamsFromUrl(su_home_t *home, url_t *u, list<string> &params) {
	for (auto it=params.begin(); it != params.end(); ++it) {
		const char *tag=it->c_str();
		if (!url_has_param(u, tag)) continue;
		char *paramcopy=su_strdup(home, u->url_params);
		u->url_params = url_strip_param_string(paramcopy, tag);
	}
}

sip_unknown_t *ModuleToolbox::getCustomHeaderByName(sip_t *sip, const char *name){
	sip_unknown_t *it;
	for(it=sip->sip_unknown;it!=NULL;it=it->un_next){
		if (strcasecmp(it->un_name,name)==0){
			return it;
		}
	}
	return NULL;
}

int ModuleToolbox::getCpuCount() {
	int count = 0;
	char line[256] = { 0 };
	
	FILE *f = fopen("/proc/cpuinfo", "r");
	if (f != NULL) {
		while (fgets(line, sizeof(line), f)) {
			if (strstr(line, "processor") == line)
				count++;
		}
		LOGI("Found %i processors", count);
		fclose(f);
	} else {
		LOGE("ModuleToolbox::getCpuCount() not implemented outside of Linux");
		count = 1;
	}
	return count;
}

