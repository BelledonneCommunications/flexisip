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
#include "transaction.hh"
#include "etchosts.hh"
#include <sstream>

#include <sofia-sip/su_md5.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/tport.h>

using namespace std;

static char const *compute_branch(nta_agent_t *sa, msg_t *msg, sip_t const *sip, char const *string_server,
								  const shared_ptr<OutgoingTransaction> &outTr);

class ForwardModule : public Module, ModuleToolbox {
  public:
	ForwardModule(Agent *ag);
	virtual void onDeclare(GenericStruct *module_config);
	virtual void onLoad(const GenericStruct *root);
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev) throw (FlexisipException);
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev) throw (FlexisipException);
	~ForwardModule();

  private:
	url_t *overrideDest(shared_ptr<RequestSipEvent> &ev, url_t *dest);
	url_t *getDestinationFromRoute(su_home_t *home, sip_t *sip);
	bool isLooping(shared_ptr<RequestSipEvent> &ev, const char *branch);
	unsigned int countVia(shared_ptr<RequestSipEvent> &ev);
	su_home_t mHome;
	sip_route_t *mOutRoute;
	bool mRewriteReqUri;
	bool mAddPath;
	static ModuleInfo<ForwardModule> sInfo;
};

ModuleInfo<ForwardModule> ForwardModule::sInfo(
	"Forward", "This module executes the basic routing task of SIP requests and pass them to the transport layer. "
			   "It must always be enabled.",
	ModuleInfoBase::ModuleOid::Forward);

ForwardModule::ForwardModule(Agent *ag) : Module(ag), mOutRoute(NULL), mRewriteReqUri(false), mAddPath(false) {
	su_home_init(&mHome);
}

ForwardModule::~ForwardModule() {
	su_home_deinit(&mHome);
}

void ForwardModule::onDeclare(GenericStruct *module_config) {
	ConfigItemDescriptor items[] = {
        {String, "route", "A sip uri where to send all requests", ""},
		{Boolean, "add-path", "Add a path header of this proxy", "true"},
		{Boolean, "rewrite-req-uri", "Rewrite request-uri's host and port according to above route", "false"},
		config_item_end};
	module_config->addChildrenValues(items);
}

void ForwardModule::onLoad(const GenericStruct *mc) {
	string route = mc->get<ConfigString>("route")->read();
	mRewriteReqUri = mc->get<ConfigBoolean>("rewrite-req-uri")->read();
	if (route.size() > 0) {
		mOutRoute = sip_route_make(&mHome, route.c_str());
		if (mOutRoute == NULL || mOutRoute->r_url->url_host == NULL) {
			LOGF("Bad route parameter '%s' in configuration of Forward module", route.c_str());
		}
	}
	mAddPath = mc->get<ConfigBoolean>("add-path")->read();
}

url_t *ForwardModule::overrideDest(shared_ptr<RequestSipEvent> &ev, url_t *dest) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();

	if (mOutRoute) {
		sip_t *sip = ms->getSip();
		for (sip_via_t *via = sip->sip_via; via != NULL; via = via->v_next) {
			if (urlViaMatch(mOutRoute->r_url, sip->sip_via, false)) {
				SLOGD << "Found forced outgoing route in via, skipping";
				return dest;
			}
		}
		if(!urlIsResolved(req_url)) {
			dest = mOutRoute->r_url;
			if(mRewriteReqUri) {
				*req_url = *dest;
			}
		}
	}
	return dest;
}

url_t *ForwardModule::getDestinationFromRoute(su_home_t *home, sip_t *sip) {
	sip_route_t *route = sip->sip_route;

	if (route) {
		char received[64] = {0};
		char rport[8] = {0};
		url_t *ret = url_hdup(home, sip->sip_route->r_url);

		url_param(route->r_url->url_params, "fs-received", received, sizeof(received));
		url_param(route->r_url->url_params, "fs-rport", rport, sizeof(rport));
		if (received[0] != 0) {
			urlSetHost(home, ret, received);
			ret->url_params = url_strip_param_string(su_strdup(home, route->r_url->url_params), "fs-received");
		}
		if (rport[0] != 0) {
			ret->url_port = su_strdup(home, rport);
			ret->url_params = url_strip_param_string(su_strdup(home, route->r_url->url_params), "fs-rport");
		}
		return ret;
	}
	return NULL;
}

static bool isUs(Agent *ag, sip_route_t *r) {
	msg_param_t param = msg_params_find(r->r_params, "fs-proxy-id");
	if (param && strcmp(param, ag->getUniqueId().c_str()) == 0)
		return true;
	return ag->isUs(r->r_url);
}

void ForwardModule::onRequest(shared_ptr<RequestSipEvent> &ev) throw(FlexisipException) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	url_t *dest = NULL;
	sip_t *sip = ms->getSip();
	msg_t *msg = ms->getMsg();

	// Check max forwards
	if (sip->sip_max_forwards != NULL && sip->sip_max_forwards->mf_count <= countVia(ev)) {
		LOGD("Too Many Hops");
		ev->reply(SIP_483_TOO_MANY_HOPS, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}
	// Decrease max forward
	if (sip->sip_max_forwards)
		--sip->sip_max_forwards->mf_count;

	dest = sip->sip_request->rq_url;
	// removes top route headers if they matches us
	while (sip->sip_route != NULL && isUs(getAgent(), sip->sip_route)) {
		LOGD("Removing top route %s", url_as_string(ms->getHome(), sip->sip_route->r_url));
		sip_route_remove(msg, sip);
	}
	if (sip->sip_route != NULL) {
		dest = getDestinationFromRoute(ms->getHome(), sip);
	}

	/* workaround bad sip uris with two @ that results in host part being "something@somewhere" */
	if ((dest->url_type != url_sip && dest->url_type != url_sips) || dest->url_host == NULL ||
		strchr(dest->url_host, '@') != 0) {
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

	// Check self-forwarding
	if (ev->getOutgoingAgent() != NULL && getAgent()->isUs(dest->url_host, dest->url_port, true)) {
		SLOGD << "Stopping request to us";
		ev->terminateProcessing();
		return;
	}

	// tport is the transport which will be used by sofia to send message
	tp_name_t name = {0, 0, 0, 0, 0, 0};
	tport_t *tport = NULL;
	if (ev->getOutgoingAgent() != NULL) {
		// tport_by_name can only work for IPs
		if (tport_name_by_url(ms->getHome(), &name, (url_string_t *)dest) == 0) {
			tport = tport_by_name(nta_agent_tports(getSofiaAgent()), &name);
			if (!tport) {
				LOGE("Could not find tport to set proper outgoing Record-Route to %s", dest->url_host);
			}
		} else
			LOGE("tport_name_by_url() failed for url %s", url_as_string(ms->getHome(), dest));
	}

	// Eventually add second record route with different transport
	// to bridge to networks: for example, we'll end with UDP, TCP.
	const sip_method_t method = ms->getSip()->sip_request->rq_method;
	if (ev->mRecordRouteAdded && (method == sip_method_invite || method == sip_method_subscribe)) {
		addRecordRoute(ms->getHome(), getAgent(), ev, tport);
	}

	// Add path
	if (mAddPath && method == sip_method_register) {
		addPathHeader(getAgent(), ev, tport, getAgent()->getUniqueId().c_str());
	}

	// Clean push notifs params from contacts
	if (sip->sip_contact && sip->sip_request->rq_method != sip_method_register) {
		removeParamsFromContacts(ms->getHome(), sip->sip_contact, sPushNotifParams);
		SLOGD << "Removed push params from contact";
	}
	removeParamsFromUrl(ms->getHome(), sip->sip_request->rq_url, sPushNotifParams);

	shared_ptr<OutgoingTransaction> outTr;
	if (ev->getOutgoingAgent() != NULL) { //== if message is to be forwarded
		outTr = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
		if (outTr == NULL && dynamic_pointer_cast<IncomingTransaction>(ev->getIncomingAgent()) != NULL) {
			// if an incoming transaction has been created, then create automatically an outgoing transaction to forward
			// the message.
			// This is required because otherwise, any response to the message will not be routed back through the
			// incoming transaction,
			// leaving it unanswered, then stuck forever.
			outTr = ev->createOutgoingTransaction();
		}
	}

	// Compute branch, output branch=XXXXX
	char const *branchStr = compute_branch(getSofiaAgent(), msg, sip, mAgent->getUniqueId().c_str(), outTr);

	if (isLooping(ev, branchStr + 7)) {
		ev->reply(SIP_482_LOOP_DETECTED, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Finally send message
	ev->send(ms, (url_string_t *)dest, NTATAG_BRANCH_KEY(branchStr), NTATAG_TPORT(tport), TAG_END());
}

unsigned int ForwardModule::countVia(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	uint32_t via_count = 0;
	for (sip_via_t *via = ms->getSip()->sip_via; via != NULL; via = via->v_next)
		++via_count;
	return via_count;
}

/*function that detects loops, does not work for requests forwarded through transaction*/
bool ForwardModule::isLooping(shared_ptr<RequestSipEvent> &ev, const char *branch) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	for (sip_via_t *via = ms->getSip()->sip_via; via != NULL; via = via->v_next) {
		if (via->v_branch != NULL && strcmp(via->v_branch, branch) == 0) {
			LOGD("Loop detected: %s", via->v_branch);
			return true;
		}
	}

	return false;
}

void ForwardModule::onResponse(shared_ptr<ResponseSipEvent> &ev) throw(FlexisipException) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	ev->send(ms);
}

static char const *compute_branch(nta_agent_t *sa, msg_t *msg, sip_t const *sip, char const *string_server,
								  const shared_ptr<OutgoingTransaction> &outTr) {
	su_md5_t md5[1];
	uint8_t digest[SU_MD5_DIGEST_SIZE];
	char branch[(SU_MD5_DIGEST_SIZE * 8 + 4) / 5 + 1] = {0};
	sip_route_t const *r;

	if (!outTr) {
		su_md5_init(md5);

		su_md5_str0update(md5, string_server);
		// su_md5_str0update(md5, port);

		url_update(md5, sip->sip_request->rq_url);
		if (sip->sip_request->rq_url->url_params) {
			// put url params in the hash too, because sofia does not do it in url_update().
			su_md5_str0update(md5, sip->sip_request->rq_url->url_params);
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
	} else {
		strncpy(branch, outTr->getBranchId().c_str(), sizeof(branch) - 1);
	}

	return su_sprintf(msg_home(msg), "branch=z9hG4bK.%s", branch);
}
