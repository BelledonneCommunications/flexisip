/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <sofia-sip/msg_addr.h>

#include <flexisip/module.hh>

#include "agent.hh"

using namespace std;
using namespace flexisip;

class NatHelper : public Module, protected ModuleToolbox {
public:
	NatHelper(Agent *ag) : Module(ag) {
	}

	~NatHelper() {
	}
	bool needToBeFixed(const shared_ptr<SipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_contact_t *ct = ms->getSip()->sip_contact;
		tport_t *primary = tport_parent(ev->getIncomingTport().get());
		return ct
				&& !url_has_param(ct->m_url, mContactVerifiedParam.c_str())
				&& !url_has_param(ct->m_url,"gr")
				&& !msg_params_find(ct->m_params, "isfocus")
				&& getAgent()->getInternalTport() != primary;
	}
	virtual void onRequest(shared_ptr<RequestSipEvent> &ev) {
		shared_ptr<MsgSip> ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		sip_request_t *rq = sip->sip_request;
		/* if we receive a request whose first via is wrong (received or rport parameters are present),
		fix any possible Contact headers with the same wrong ip address and ports */
		if (needToBeFixed(ev))
			fixContactFromVia(ms->getHome(), sip, sip->sip_via);

		// processing of requests that may establish a dialog.
		if (rq->rq_method == sip_method_invite || rq->rq_method == sip_method_subscribe) {
			if (sip->sip_to->a_tag == NULL) {
				// fix potential record-route from a natted proxy added before us
				if (mFixRecordRoutes)
					fixRecordRouteInRequest(ms);
				addRecordRouteIncoming(getAgent(), ev);
			}
		}
		// fix potential Path header inserted before us by a flexisip natted proxy
		if (rq->rq_method == sip_method_register && sip->sip_path &&
			url_has_param(sip->sip_path->r_url, "fs-proxy-id")) {
			// note: why limiting this to flexisip ? it could fix any path header, even without fs-proxy-id param.
			fixPath(ms);
		}
		// Idea for future: for the case where a natted proxy forwards a REGISTER (which can be detected , we could add
		// a Path header corresponding to this proxy
	}

	/* TODO: Fixing contacts in responses is unreliable: we can't know if we are the first hop of the response.
	 * This feature should be removed from Flexisip.
	 */
	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev) {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_status_t *st = ms->getSip()->sip_status;
		sip_cseq_t *cseq = ms->getSip()->sip_cseq;
		/*in responses that establish a dialog, masquerade Contact so that further requests (including the ACK) are
		 * routed in the same way*/
		if (cseq && (cseq->cs_method == sip_method_invite || cseq->cs_method == sip_method_subscribe)) {
			if (st->st_status >= 200 && st->st_status <= 299) {
				sip_contact_t *ct = ms->getSip()->sip_contact;
				if (ct) {
					bool isVerified = url_has_param(ct->m_url, mContactVerifiedParam.c_str());
					bool isLastHop = ms->getSip()->sip_via && ms->getSip()->sip_via->v_next && !ms->getSip()->sip_via->v_next->v_next;
					if (isLastHop){
						if (isVerified){
							// Via contains client and first proxy
							LOGD("Removing verified param from response contact");
							ct->m_url->url_params = url_strip_param_string(su_strdup(ms->getHome(), ct->m_url->url_params),
															 mContactVerifiedParam.c_str());
						}
					}else{
						if (needToBeFixed(ev)) {
							fixContactInResponse(ms->getHome(), ms->getMsg(), ms->getSip());
						}
						/* The "verified" param must be added whenever we fix or not the Contact, in order
						 * to signal other nodes processing this response that the contact has been 
						 * processed already. */
						if (!isVerified){
							url_param_add(ms->getHome(), ct->m_url, mContactVerifiedParam.c_str());
						}
					}
				}
			}
		}
	}

protected:
	enum RecordRouteFixingPolicy { Safe, Always };
	virtual void onDeclare(GenericStruct *module_config) {
		ConfigItemDescriptor items[] = {
			{String, "contact-verified-param",
			 "Internal URI parameter added to response contact by first proxy and cleaned by last one.", "verified"},
			{Boolean, "fix-record-routes",
			 "Fix record-routes, to workaround proxies behind firewalls but not aware of it.", "false"},
			{String, "fix-record-routes-policy",
			 "Policy to recognize nat'd record-route and fix them. There are two modes: 'safe' and 'always'", "safe"},
			config_item_end};
		module_config->addChildrenValues(items);
	}
	virtual void onLoad(const GenericStruct *sec) {
		mContactVerifiedParam = sec->get<ConfigString>("contact-verified-param")->read();
		mFixRecordRoutes = sec->get<ConfigBoolean>("fix-record-routes")->read();
		string rr_policy = sec->get<ConfigString>("fix-record-routes-policy")->read();
		if (rr_policy == "safe") {
			mRRPolicy = Safe;
		} else if (rr_policy == "always") {
			mRRPolicy = Always;
		} else {
			LOGF("NatHelper: Unsupported value '%s' for fix-record-routes-policy parameter", rr_policy.c_str());
		}
	}

private:
	string mContactVerifiedParam;
	bool empty(const char *value) {
		return value == NULL || value[0] == '\0';
	}
	void fixContactInResponse(su_home_t *home, msg_t *msg, sip_t *sip) {
		const su_addrinfo_t *ai = msg_addrinfo(msg);
		const sip_via_t *via = sip->sip_via;
		const char *via_transport = sip_via_transport(via);
		char ct_transport[20] = {0};
		if (ai != NULL) {
			char ip[NI_MAXHOST];
			char port[NI_MAXSERV];
			int err = getnameinfo(ai->ai_addr, ai->ai_addrlen, ip, sizeof(ip), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
			if (err != 0) {
				LOGE("getnameinfo() error: %s", gai_strerror(err));
			} else {
				sip_contact_t *ctt = sip->sip_contact;
				if (ctt && ctt->m_url->url_host) {
					if (!ModuleToolbox::urlHostMatch(ctt->m_url, ip) || !sipPortEquals(ctt->m_url->url_port, port)) {
						LOGD("Response is coming from %s:%s, fixing contact", ip, port);
						ModuleToolbox::urlSetHost(home, ctt->m_url, ip);
						ctt->m_url->url_port = su_strdup(home, port);
					} else
						LOGD("Contact in response is correct.");
					url_param(ctt->m_url->url_params, "transport", ct_transport, sizeof(ct_transport) - 1);
					fixTransport(home, ctt->m_url, via_transport);
				}
			}
		}
	}
	void fixContactFromVia(su_home_t *home, sip_t *msg, const sip_via_t *via) {
		sip_contact_t *ctt = msg->sip_contact;
		const char *received = via->v_received;
		const char *rport = via->v_rport;
		const char *via_transport = sip_via_transport(via);
		bool is_frontend = (via->v_next == NULL); /*true if we are the first proxy the request is walking through*/
		bool single_contact = (ctt != NULL && ctt->m_next == NULL);

		if (empty(received) && empty(rport))
			return; /*nothing to do*/

		if (empty(received)) {
			/*case where the rport is not empty  but received is empty (because the host was correct)*/
			received = via->v_host;
		}

		if (rport == NULL)
			rport = via->v_port; // if no rport is given, then trust the via port.

		for (; ctt != NULL; ctt = ctt->m_next) {
			if (ctt->m_url->url_host) {
				const char *host = ctt->m_url->url_host;
				char ct_transport[20] = {0};
				if (url_has_param(ctt->m_url,"gr")) {
					SLOGD << "Gruu found in contact header ["<<ctt<<"] for message ["<< msg << "] skipping nat fixing process for contact";
					continue;
				}
				url_param(ctt->m_url->url_params, "transport", ct_transport, sizeof(ct_transport) - 1);
				// If we have a single contact and we are the front-end proxy, or if we found a ip:port in a contact that
				// seems incorrect because the same appeared fixed in the via, then fix it.
				if ((is_frontend && single_contact) || (ModuleToolbox::urlHostMatch(host, via->v_host) &&
														sipPortEquals(ctt->m_url->url_port, via->v_port) &&
														transportEquals(via_transport, ct_transport))) {

					if (!ModuleToolbox::urlHostMatch(host, received) || !sipPortEquals(ctt->m_url->url_port, rport)) {
						LOGD("Fixing contact header with %s:%s to %s:%s", ctt->m_url->url_host,
							 ctt->m_url->url_port ? ctt->m_url->url_port : "", received, rport ? rport : "");
						ModuleToolbox::urlSetHost(home, ctt->m_url, received);
						ctt->m_url->url_port = rport;
					}
					fixTransport(home, ctt->m_url, via_transport);
				}
			}
		}
	}
	void fixTransport(su_home_t *home, url_t *url, const char *transport) {
		if (url_has_param(url, "transport")) {
			url->url_params = url_strip_param_string(su_strdup(home, url->url_params), "transport");
		}
		if (url->url_type != url_sips) {
			const char *url_transport = NULL;
			if (strcasecmp(transport, "TCP") == 0)
				url_transport = "tcp";
			else if (strcasecmp(transport, "TLS") == 0)
				url_transport = "tls";
			if (url_transport)
				url_param_add(home, url, su_sprintf(home, "transport=%s", url_transport));
		}
	}
	void fixPath(shared_ptr<MsgSip> &ms) {
		sip_t *sip = ms->getSip();
		const sip_via_t *via = sip->sip_via;
		const char *received = via->v_received;
		const char *rport = via->v_rport;
		const char *transport = sip_via_transport(via);

		url_t *path = sip->sip_path->r_url;
		if (empty(received))
			received = via->v_host;
		if (!rport)
			rport = via->v_port;
		if (!transport)
			transport = "udp";
		ModuleToolbox::urlSetHost(ms->getHome(), path, received);
		path->url_port = rport;
		fixTransport(ms->getHome(), path, transport);
	}
	bool isPrivateAddress(const char *host) {
		return strstr(host, "10.") == host || strstr(host, "192.168.") == host || strstr(host, "176.12.") == host;
	}
	void fixRecordRouteInRequest(shared_ptr<MsgSip> &ms) {
		sip_t *sip = ms->getSip();
		if (sip->sip_record_route) {
			if (mRRPolicy == Safe) {
				if (urlViaMatch(sip->sip_record_route->r_url, sip->sip_via, false)) {
					const char *transport = sip_via_transport(sip->sip_via);
					LOGD("Record-route and via are matching.");
					if (sip->sip_via->v_received) {
						LOGD("This record-route needs to be fixed for host");
						url_param_add(
							ms->getHome(),
							sip->sip_record_route->r_url,
							su_sprintf(ms->getHome(), "fs-received=%s", sip->sip_via->v_received)
						);
					}
					if (sip->sip_via->v_rport) {
						LOGD("This record-route needs to be fixed for port");
						url_param_add(
							ms->getHome(),
							sip->sip_record_route->r_url,
							su_sprintf(ms->getHome(), "fs-rport=%s", sip->sip_via->v_rport)
						);
					}
					fixTransport(ms->getHome(), sip->sip_record_route->r_url, transport);
				}
			} else {
				const char *host = sip->sip_record_route->r_url->url_host;
				if (host && isPrivateAddress(host)) {
					const char *transport = sip_via_transport(sip->sip_via);
					const char *received = sip->sip_via->v_received ? sip->sip_via->v_received : sip->sip_via->v_host;
					const char *rport = sip->sip_via->v_rport ? sip->sip_via->v_rport : sip->sip_via->v_port;
					if (!ModuleToolbox::urlHostMatch(received, host)) {
						LOGD("This record-route needs to be fixed for host");
						url_param_add(
							ms->getHome(), sip->sip_record_route->r_url,
							su_sprintf(ms->getHome(), "fs-received=%s", received)
						);
					}
					if (!sipPortEquals(rport, sip->sip_record_route->r_url->url_port, transport)) {
						LOGD("This record-route needs to be fixed for port");
						url_param_add(
							ms->getHome(), sip->sip_record_route->r_url,
							su_sprintf(ms->getHome(), "fs-rport=%s", rport)
						);
					}
					fixTransport(ms->getHome(), sip->sip_record_route->r_url, transport);
				}
			}
		}
	}
	bool mFixRecordRoutes;
	RecordRouteFixingPolicy mRRPolicy;
	static ModuleInfo<NatHelper> sInfo;
};

ModuleInfo<NatHelper> NatHelper::sInfo(
	"NatHelper",
	"The NatHelper module executes small tasks to make SIP work smoothly despite firewalls. It corrects the Contact "
	"headers that contain obviously inconsistent addresses, and adds a Record-Route to ensure subsequent requests are "
	"routed also by the proxy, through the same UDP or TCP channel used for the initial request.",
	{ "GarbageIn" },
	ModuleInfoBase::ModuleOid::NatHelper
);
