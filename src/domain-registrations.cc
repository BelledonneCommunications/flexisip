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

#include "domain-registrations.hh"
#include "agent.hh"
#include "module.hh"

#include <sofia-sip/nta_stateless.h>
#include <sofia-sip/nth.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nta_tport.h>

#include <fstream>
#include <sstream>


using namespace::std;

DomainRegistrationManager::DomainRegistrationManager(Agent *agent) : mAgent(agent){
	GenericManager *mgr = GenericManager::get();
	GenericStruct *domainRegistrationCfg = new GenericStruct("inter-domain-connections", 
		"Inter domain connections is a set of feature allowing to dynamically connect several flexisip servers together in order to manage SIP routing at local and global"
		" scope. Let's suppose you have two SIP network a.example.net and b.example.net run privately and independently (no one from a.example.net "
		"needs to call someone at b.example.net). However, when people from a and b are outside of their network, they register to a worldwide available "
		"flexisip instance running on 'global.example.net'. It is then possible to:\n"
		"* have calls made within a.example.net routed locally and sent to global.example.net in order to reach users inside and outside of a's network."
		" Example: 1@a.example.net calls 2@a.example.net. If 2 is registered on a.example.net then the call is routed locally. On the contrary if 2 is"
		" absent and registered, the call is then sent to global.example.net and then routed by the global proxy.\n"
		"* when global.example.net receives a call from a user not within its native network (ex: 1@a.example.net calls 2@a.example.net), "
		"it can route this call to the proxy that is responsible for managing the local domain (a.example.net).\n"
		"This system is dynamic, that is the physical IP address of a and b network can change (dynamic ip address)\n."
		"This scenario is achieved with two key features:\n"
		"* a.example.net sends a REGISTER to global.example.net to indicate that it is the responsible for the entire domain a.example.net."
		" The global.example.net authenticates this REGISTER thanks to TLS client certificate presented by a.example.net.\n"
		"* global.example.net is configured to accept this domain registration and route all calls it receives directly and estinated to a.example.net domain"
		" through the connection established by a.example.net during the domain registration."
		, ModuleInfoBase::InterProxyCommunications);
	
	mgr->getRoot()->addChild(domainRegistrationCfg);
	
	ConfigItemDescriptor configs[] = {
		{ Boolean , "accept-domain-registrations", "Whether flexisip shall accept registrations for entire domains", "false"},
		{ String , "domain-registrations", "Path to a text file describing the domain registrations to make. This file must contains lines like:\n"
							" <local domain name> <SIP URI of proxy/registrar where to send the domain REGISTER>\n"
							" where:\n"
							" <local domain name> is a domain name managed locally by this proxy\n"
							" <SIP URI of proxy/registrar> is the SIP URI where the domain registration will be sent. The special uri parameter"
							" 'tls-certificate-dir' is understood in order to specify a TLS client certificate to present to the remote proxy.\n"
							" If the file is absent or empty, no registrations are done."
							, "/etc/flexisip/domain-registrations.conf"},
		config_item_end
	};
	
	
	domainRegistrationCfg->addChildrenValues(configs);
	
}


DomainRegistrationManager::~DomainRegistrationManager() {

}

int DomainRegistrationManager::load() {
	ifstream ifs;
	string configFile;
	
	GenericStruct *domainRegistrationCfg = GenericManager::get()->getRoot()->get<GenericStruct>("inter-domain-connections");
	configFile = domainRegistrationCfg->get<ConfigString>("domain-registrations")->read();
	
	if (configFile.empty()) return 0;
	
	ifs.open(configFile);
	if (!ifs.is_open()) {
		LOGE("Cannot open domain registration configuration file '%s'", configFile.c_str());
		return -1;
	}
	do{
		SofiaAutoHome home;
		string line;
		string domain,uri;
		getline(ifs, line);
		istringstream istr(line);
		istr>>domain;
		istr>>uri;
		if (domain.empty()) continue; /*empty line */
		if (uri.empty()) {
			LOGE("Empty URI in domain registration definition.");
			goto error;
		}
		url_t *url = url_make(home.home(), uri.c_str());
		if (!url){
			LOGE("Bad URI '%s' in domain registration definition.", uri.c_str());
			goto error;
		}
		/*extract the certificate directory parameter if given, and remove it before passing the URI to the DomainRegistration object*/
		char clientCertdir[256]={0};
		if (url_param(url->url_params, "tls-certificates-dir", clientCertdir, sizeof(clientCertdir))>0){
			url->url_params = url_strip_param_string(su_strdup(home.home(), url->url_params), "tls-certificates-dir");
		}
		auto dr = make_shared<DomainRegistration>(*this, domain, url, clientCertdir);
		mRegistrations.push_back(dr);
	}while(!ifs.eof() && !ifs.bad());
	
	for_each(mRegistrations.begin(), mRegistrations.end(), mem_fn(&DomainRegistration::start));
	return 0;
error:
	LOGF("Syntax error parsing domain registration configuration file '%s'", configFile.c_str());
	return -1;
}


DomainRegistration::DomainRegistration(DomainRegistrationManager& mgr, const string& localDomain, const url_t* parent_proxy, const string& clientCertdir )
	: mManager(mgr){
	char transport[64]={0};
	url_t *tportUri;
	tp_name_t tpn = {0};
	bool usingTls;
	nta_agent_t *agent = mManager.mAgent->getSofiaAgent();
	
	su_home_init(&mHome);
	mFrom = url_format(&mHome, "%s:%s", parent_proxy->url_type == url_sips ? "sips" : "sip", localDomain.c_str());
	mProxy = url_hdup(&mHome, parent_proxy);
	
	url_param(parent_proxy->url_params,"transport", transport, sizeof(transport)-1);
	
	usingTls =  parent_proxy->url_type == url_sips || strcasecmp(transport, "tls")==0;
	
	tportUri = url_format(&mHome, "%s:*:*", usingTls ? "sips" : "sip");
	
	if (usingTls && !clientCertdir.empty()){
		nta_agent_add_tport(agent, (url_string_t*)tportUri, TPTAG_CERTIFICATE(clientCertdir.c_str()), TPTAG_IDENT(localDomain.c_str()), TAG_END());
	}else{
		nta_agent_add_tport(agent, (url_string_t*)tportUri, TPTAG_IDENT(localDomain.c_str()), TAG_END());
	}
	tpn.tpn_ident = localDomain.c_str();
	mPrimaryTport = tport_by_name(nta_agent_tports(agent), &tpn);
	if (!mPrimaryTport){
		LOGF("Could not find the tport we just added in the agent.");
	}
	
	mLeg = nta_leg_tcreate(agent, sLegCallback, (nta_leg_magic_t*)this, NTATAG_METHOD("REGISTER"),
					SIPTAG_FROM(sip_from_create(&mHome, (url_string_t*)mFrom)),
					SIPTAG_TO(sip_to_create(&mHome, (url_string_t*) mFrom)),
					URLTAG_URL(mProxy),
					TAG_END());
	if (!mLeg){
		LOGF("Could not create leg");
	}
	mCurrentTport = NULL;
	mTimer = NULL;
}

int DomainRegistration::sLegCallback ( nta_leg_magic_t* ctx, nta_leg_t* leg, nta_incoming_t* incoming, const sip_t* request ) {
	LOGE("legCallback called");
	return 500;
}

void DomainRegistration::sRefreshRegistration(su_root_magic_t *magic, su_timer_t *timer, su_timer_arg_t *arg){
	static_cast<DomainRegistration*>(arg)->start();
}

int DomainRegistration::getExpires( nta_outgoing_t* orq, const sip_t* response ) {
	int expires;
	if (response->sip_expires) return response->sip_expires->ex_delta;
	if (response->sip_contact && response->sip_contact->m_expires){
		expires = atoi(response->sip_contact->m_expires);
		if (expires > 0) return expires;
	}
	msg_t *req = nta_outgoing_getrequest(orq);
	sip_t *sip = (sip_t*)msg_object(req);
	expires = sip->sip_expires->ex_delta;
	msg_unref(req); //because nta_outgoing_getrequest() gives a new reference.
	return expires;
}

void DomainRegistration::onConnectionBroken(tport_t* tport, msg_t* msg, int error) {
	//restart registration...
	start();
}

void DomainRegistration::sOnConnectionBroken(tp_stack_t* stack, tp_client_t* client, tport_t* tport, msg_t* msg, int error ) {
	reinterpret_cast<DomainRegistration*>(client)->onConnectionBroken(tport, msg, error);
}

void DomainRegistration::responseCallback(nta_outgoing_t *orq, const sip_t *resp){
	int nextSchedule;
	
	if (mTimer){
		su_timer_destroy(mTimer);
		mTimer = NULL;
	}
	mTimer = su_timer_create(su_root_task(mManager.mAgent->getRoot()), 0);
	if (resp){
		SofiaAutoHome home;
		msg_t *msg = nta_outgoing_getresponse(orq);
		SLOGD<<"DomainRegistration::responseCallback(): receiving response:"<<endl<<msg_as_string(home.home(), msg, msg_object(msg), 0, NULL); 
		msg_unref(msg);
	}
	
	if (!resp || resp->sip_status->st_status != 200){
		/*the registration failed for whatever reason. Retry shortly.*/
		nextSchedule = 30;
		LOGD("Domain registration for %s failed, will retry in %i seconds", mFrom->url_host, nextSchedule);
		su_timer_set_interval(mTimer, &DomainRegistration::sRefreshRegistration, this, (su_duration_t)nextSchedule*1000);
	}else{
		tport_t *tport = nta_outgoing_transport(orq);
		cleanCurrentTport();
		mCurrentTport = tport;
		mPendId = tport_pend(tport, NULL, &DomainRegistration::sOnConnectionBroken, (tp_client_t*)this);
		nextSchedule = ((getExpires(orq, resp) * 90) / 100 ) + 1;
		LOGD("Scheduling next domain register refresh for %s in %i seconds", mFrom->url_host, nextSchedule);
		su_timer_set_interval(mTimer, &DomainRegistration::sRefreshRegistration, this, (su_duration_t)nextSchedule*1000);
		
	}
}

int DomainRegistration::sResponseCallback(nta_outgoing_magic_t *ctx, nta_outgoing_t *orq, const sip_t *resp){
	reinterpret_cast<DomainRegistration*>(ctx)->responseCallback(orq, resp);
	return 0;
}

DomainRegistration::~DomainRegistration() {
	su_home_deinit(&mHome);
}

void DomainRegistration::setContact(msg_t *msg) {
	sip_t *sip = (sip_t*)msg_object(msg);
	if (sip->sip_contact == NULL){
		sip->sip_contact = sip_contact_create(msg_home(msg), (url_string_t*)mFrom, NULL);
	}
}

void DomainRegistration::start() {
	msg_t *msg;
	
	if (mTimer){
		su_timer_destroy(mTimer);
		mTimer = NULL;
	}
	
	msg = nta_msg_create(mManager.mAgent->getSofiaAgent(), 0);
	if (nta_msg_request_complete(msg, mLeg, sip_method_register, NULL, (url_string_t*)mProxy) != 0){
		LOGE("nta_msg_request_complete() failed");
	}
	msg_header_insert(msg, msg_object(msg), (msg_header_t*)sip_expires_create(msg_home(msg), 3600));
	setContact(msg);
	sip_complete_message(msg);
	msg_serialize(msg, msg_object(msg));
	su_home_t home;
	su_home_init(&home);
	LOGD("Domain registration about to be sent:\n%s",msg_as_string(&home, msg, msg_object(msg), 0, NULL));
	su_home_deinit(&home);
	
	nta_outgoing_t *outgoing = nta_outgoing_mcreate(mManager.mAgent->getSofiaAgent(), sResponseCallback, (nta_outgoing_magic_t*) this, NULL, msg, 
				NTATAG_TPORT(mPrimaryTport),
				TAG_END());
	if (!outgoing){
		LOGE("Could not create outgoing transaction");
		return;
	}
	
}

void DomainRegistration::cleanCurrentTport() {
	if (mCurrentTport){
		tport_release(mCurrentTport, mPendId, NULL, NULL, (tp_client_t*)this, 0);
		tport_unref(mCurrentTport);
		mCurrentTport = NULL;
		mPendId = 0;
	}
}


void DomainRegistration::stop() {
	cleanCurrentTport();
	if (mTimer) {
		su_timer_destroy(mTimer);
		mTimer = NULL;
	}
}
