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

#include "module.hh"
#include "agent.hh"
#include "transaction.hh"
#include "etchosts.hh"
#include <sstream>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/tport.h>

using namespace ::std;

static char const *compute_branch(nta_agent_t *sa, msg_t *msg, sip_t const *sip, char const *string_server);

class ForwardModule: public Module, ModuleToolbox {
public:
	ForwardModule(Agent *ag);
	virtual void onDeclare(GenericStruct * module_config);
	virtual void onLoad(const GenericStruct *root);
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);
	~ForwardModule();
private:
	url_t* overrideDest(shared_ptr<RequestSipEvent> &ev, url_t* dest);
	tport_t * checkRecordRoutes(shared_ptr<RequestSipEvent> &ev, url_t *dest);
	bool isLooping(shared_ptr<RequestSipEvent> &ev, const char * branch);
	unsigned int countVia(shared_ptr<RequestSipEvent> &ev);
	su_home_t mHome;
	sip_route_t *mOutRoute;
	bool mRewriteReqUri;
	static ModuleInfo<ForwardModule> sInfo;
};

ModuleInfo<ForwardModule> ForwardModule::sInfo("Forward",
		"This module executes the basic routing task of SIP requests and pass them to the transport layer. "
		"It must always be enabled.",
		ModuleInfoBase::ModuleOid::Forward);

ForwardModule::ForwardModule(Agent *ag) :
		Module(ag) {
	su_home_init(&mHome);
	mOutRoute = NULL;
}

ForwardModule::~ForwardModule() {
	su_home_deinit(&mHome);
}

void ForwardModule::onDeclare(GenericStruct * module_config) {
	ConfigItemDescriptor items[] = {
			{ String, "route", "A sip uri where to send all requests", "" },
			{ Boolean, "rewrite-req-uri", "Rewrite request-uri's host and port according to above route", "false" },
			config_item_end
	};
	module_config->addChildrenValues(items);
}

void ForwardModule::onLoad(const GenericStruct *module_config) {
	string route = module_config->get<ConfigString>("route")->read();
	mRewriteReqUri = module_config->get<ConfigBoolean>("rewrite-req-uri")->read();
	if (route.size() > 0) {
		mOutRoute = sip_route_make(&mHome, route.c_str());
		if (mOutRoute == NULL || mOutRoute->r_url->url_host == NULL) {
			LOGF("Bad route parameter '%s' in configuration of Forward module", route.c_str());
		}
	}
}

url_t* ForwardModule::overrideDest(shared_ptr<RequestSipEvent> &ev, url_t *dest) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	if (mOutRoute) {
		dest = mOutRoute->r_url;
		if (mRewriteReqUri) {
			ms->getSip()->sip_request->rq_url->url_host = mOutRoute->r_url->url_host;
			ms->getSip()->sip_request->rq_url->url_port = mOutRoute->r_url->url_port;
		}
	}
	return dest;
}

/* the goal of this method is to check whether we added ourself to the record route, and handle a possible
 transport change by adding a new record-route with transport updated.
 Typically, if we transfer an INVITE from TCP to UDP, we should find two consecutive record-route, first one with UDP, and second one with TCP
 so that further request from both sides are sent to the appropriate transport of flexisip, and also we don't ask to a UDP only equipment to route to TCP.
 */
tport_t * ForwardModule::checkRecordRoutes(shared_ptr<RequestSipEvent> &ev, url_t *dest) {
	if (!ev->mRecordRouteAdded)
		return NULL; //if no record route were added by any module, no need to set an outgoing record route.
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_method_t method=ms->getSip()->sip_request->rq_method;
	if (method==sip_method_invite || method==sip_method_subscribe){
		tp_name_t name={0};
		tport_name_by_url(ms->getHome(),&name,(url_string_t*)dest);
		tport_t *tport=tport_by_name(nta_agent_tports(getSofiaAgent()),&name);
		if (tport){
			addRecordRoute(ms->getHome(),getAgent(),ev,tport);
			return tport;
		}else{
			LOGE("Could not find tport to set proper outgoing Record-Route.");
		}
	}
	return NULL;
}

void ForwardModule::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	url_t* dest = NULL;
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();

	// Check max forwards
	if (sip->sip_max_forwards != NULL && sip->sip_max_forwards->mf_count <= countVia(ev)) {
		LOGD("Too Many Hops");
		ev->reply(SIP_483_TOO_MANY_HOPS, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	dest = sip->sip_request->rq_url;
	// removes top route headers if they matches us
	while (sip->sip_route != NULL && getAgent()->isUs(sip->sip_route->r_url)) {
		LOGD("Removing top route %s", url_as_string(ms->getHome(), sip->sip_route->r_url));
		sip_route_remove(msg, sip);
	}
	if (sip->sip_route != NULL) {
		/*forward to this route*/
		dest = sip->sip_route->r_url;
	}

	/* workaround bad sip uris with two @ that results in host part being "something@somewhere" */
	if ((dest->url_type!=url_sip && dest->url_type!=url_sips)
		|| dest->url_host==NULL || strchr(dest->url_host, '@') != 0) {
		ev->reply(SIP_400_BAD_REQUEST, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	dest = overrideDest(ev, dest);

	string ip;
	if (EtcHostsResolver::get()->resolve(dest->url_host, &ip)) {
		LOGD("Found %s in /etc/hosts", dest->url_host);
		/* duplication of dest because we don't want to modify the message with our name resolution result*/
		dest = url_hdup(ms->getHome(), dest);
		dest->url_host = ip.c_str();
	}

	// Compute branch, output branch=XXXXX
	char const * branchStr = compute_branch(getSofiaAgent(), msg, sip, mAgent->getUniqueId().c_str());

	// Check looping
	if (isLooping(ev, branchStr + 7)) {
		ev->reply(SIP_482_LOOP_DETECTED, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else if (getAgent()->isUs(dest->url_host, dest->url_port, false)) {
		SLOGD << "Skipping forwarding of request to us "
			<< url_as_string(ms->getHome(), dest) << "\n" << ms;
		ev->terminateProcessing();
	} else {
		tport_t *tport=checkRecordRoutes(ev, dest);
		if (sip->sip_max_forwards) --sip->sip_max_forwards->mf_count;
		//since checkRecordRoutes() may find appropriate tport, avoid sofia to search it again.
		if (tport)
			ev->send(ms, (url_string_t*) dest, NTATAG_BRANCH_KEY(branchStr), NTATAG_TPORT(tport), TAG_END());
		else
			ev->send(ms, (url_string_t*) dest, NTATAG_BRANCH_KEY(branchStr), TAG_END());
	}

}

unsigned int ForwardModule::countVia(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	uint32_t via_count = 0;
	for (sip_via_t *via = ms->getSip()->sip_via; via != NULL; via = via->v_next)
		++via_count;
	return via_count;
}

bool ForwardModule::isLooping(shared_ptr<RequestSipEvent> &ev, const char * branch) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	for (sip_via_t *via = ms->getSip()->sip_via; via != NULL; via = via->v_next) {
		if (via->v_branch != NULL && strcmp(via->v_branch, branch) == 0) {
			LOGD("Loop detected: %s", via->v_branch);
			return true;
		}
	}

	return false;
}

void ForwardModule::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	ev->send(ms, (url_string_t*) NULL, TAG_END());
}

#include <sofia-sip/su_md5.h>
static char const *compute_branch(nta_agent_t *sa, msg_t *msg, sip_t const *sip, char const *string_server) {
	su_md5_t md5[1];
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	char branch[(SU_MD5_DIGEST_SIZE * 8 + 4) / 5 + 1];
	sip_route_t const *r;

	su_md5_init(md5);

	su_md5_str0update(md5, string_server);
	//su_md5_str0update(md5, port);

	url_update(md5, sip->sip_request->rq_url);
	if (sip->sip_request->rq_url->url_params){
		//put url params in the hash too, because sofia does not do it in url_update().
		su_md5_str0update(md5,sip->sip_request->rq_url->url_params);
	}
	if (sip->sip_call_id) {
		su_md5_str0update(md5, sip->sip_call_id->i_id);
	}
	if (sip->sip_from) {
		url_update(md5, sip->sip_from->a_url);
		su_md5_stri0update(md5, sip->sip_from->a_tag);
	}
	if (sip->sip_to) {
		url_update(md5, sip->sip_to->a_url);
		/* XXX - some broken implementations include To tag in CANCEL */
		/* su_md5_str0update(md5, sip->sip_to->a_tag); */
	}
	if (sip->sip_cseq) {
		uint32_t cseq = htonl(sip->sip_cseq->cs_seq);
		su_md5_update(md5, &cseq, sizeof(cseq));
	}

	for (r = sip->sip_route; r; r = r->r_next)
		url_update(md5, r->r_url);

	su_md5_digest(md5, digest);

	msg_random_token(branch, sizeof(branch) - 1, digest, sizeof(digest));

	return su_sprintf(msg_home(msg), "branch=z9hG4bK.%s", branch);
}

