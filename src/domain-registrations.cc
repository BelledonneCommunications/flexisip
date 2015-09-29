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

#include <sofia-sip/nta_stateless.h>
#include <sofia-sip/nth.h>
#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/nta_tport.h>

using namespace::std;

DomainRegistrationManager::DomainRegistrationManager(nta_agent_t *agent) : mAgent(agent){
}


DomainRegistrationManager::~DomainRegistrationManager() {

}

int DomainRegistrationManager::load(const string& configFile) {
	su_home_t home;
	su_home_init(&home);
	auto dr = make_shared<DomainRegistration>(*this, "local.linphone.org", url_make(&home, "sip:sip.linphone.org;transport=tcp"), "");
	mRegistrations.push_back(dr);
	dr->start();
	su_home_deinit(&home);
	return 0;
}


DomainRegistration::DomainRegistration(DomainRegistrationManager& mgr, const string& localDomain, const url_t* parent_proxy, const string& clientCertdir )
	: mManager(mgr){
	char transport[64]={0};
	url_t *tportUri;
	tp_name_t tpn = {0};
	bool usingTls;
	
	su_home_init(&mHome);
	mFrom = url_format(&mHome, "%s:%s", parent_proxy->url_type == url_sips ? "sips" : "sip", localDomain.c_str());
	mProxy = url_hdup(&mHome, parent_proxy);
	
	url_param(parent_proxy->url_params,"transport", transport, sizeof(transport)-1);
	
	usingTls =  parent_proxy->url_type == url_sips || strcasecmp(transport, "tls")==0;
	
	tportUri = url_format(&mHome, "%s:*:*", usingTls ? "sips" : "sip");
	
	if (usingTls && !clientCertdir.empty()){
		nta_agent_add_tport(mManager.mAgent, (url_string_t*)tportUri, TPTAG_CERTIFICATE(clientCertdir.c_str()), TPTAG_IDENT(localDomain.c_str()), TAG_END());
	}else{
		nta_agent_add_tport(mManager.mAgent, (url_string_t*)tportUri, TPTAG_IDENT(localDomain.c_str()), TAG_END());
	}
	tpn.tpn_ident = localDomain.c_str();
	mTport = tport_by_name(nta_agent_tports(mManager.mAgent), &tpn);
	if (!mTport){
		LOGF("Could not find the tport we just added in the agent.");
	}
	
	mLeg = nta_leg_tcreate(mManager.mAgent, legCallback, (nta_leg_magic_t*)this, NTATAG_METHOD("REGISTER"),
					SIPTAG_FROM(sip_from_create(&mHome, (url_string_t*)mFrom)),
					SIPTAG_TO(sip_to_create(&mHome, (url_string_t*) mFrom)),
					URLTAG_URL(mProxy),
					TAG_END());
	if (!mLeg){
		LOGF("Could not create leg");
	}
	
	mTimer = NULL;
}

int DomainRegistration::legCallback ( nta_leg_magic_t* ctx, nta_leg_t* leg, nta_incoming_t* incoming, const sip_t* request ) {
	LOGE("legCallback called");
	return 500;
}

int DomainRegistration::responseCallback(nta_outgoing_magic_t *ctx, nta_outgoing_t *orq, const sip_t *resp){
	LOGD("DomainRegistration::responseCallback");
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
	msg = nta_msg_create(mManager.mAgent, 0);
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
	
	nta_outgoing_t *outgoing = nta_outgoing_mcreate(mManager.mAgent, responseCallback, (nta_outgoing_magic_t*) this, NULL, msg, 
				NTATAG_TPORT(mTport),
				TAG_END());
	if (!outgoing){
		LOGE("Could not create outgoing transaction");
		return;
	}
	
}

void DomainRegistration::stop() {
	if (mTimer) su_timer_destroy(mTimer);
}
