/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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

#include "contact-correction-strategy.hh"

#include <memory>
#include <string>

#include "flexisip/event.hh"
#include "flexisip/module.hh"

#include "agent.hh"

using namespace std;

namespace flexisip {

ContactCorrectionStrategy::Helper::Helper(const std::string& parameter) : mContactCorrectionParameter(parameter) {
}

/*
 * Fix "Contact" header field present in request response.
 */
void ContactCorrectionStrategy::Helper::fixContactInResponse(su_home_t* home, msg_t* msg, sip_t* sip) {
	const su_addrinfo_t* ai = msg_addrinfo(msg);
	const sip_via_t* via = sip->sip_via;
	const char* via_transport = sip_via_transport(via);
	char ct_transport[20] = {0};
	if (ai != NULL) {
		char ip[NI_MAXHOST];
		char port[NI_MAXSERV];
		int err = getnameinfo(ai->ai_addr, ai->ai_addrlen, ip, sizeof(ip), port, sizeof(port),
		                      NI_NUMERICHOST | NI_NUMERICSERV);
		if (err != 0) {
			LOGE("getnameinfo() error: %s", gai_strerror(err));
		} else {
			sip_contact_t* ctt = sip->sip_contact;
			if (ctt && ctt->m_url->url_host) {
				if (!ModuleToolbox::urlHostMatch(ctt->m_url, ip) ||
				    !ModuleToolbox::sipPortEquals(ctt->m_url->url_port, port)) {
					LOGD("Response is coming from %s:%s, fixing contact", ip, port);
					ModuleToolbox::urlSetHost(home, ctt->m_url, ip);
					ctt->m_url->url_port = su_strdup(home, port);
				} else LOGD("Contact in response is correct.");
				url_param(ctt->m_url->url_params, "transport", ct_transport, sizeof(ct_transport) - 1);
				NatTraversalStrategy::Helper::fixTransport(home, ctt->m_url, via_transport);
			}
		}
	}
}

/*
 * Fix "Contact" header field using "rport" and "received" information from the "VIA" header field.
 */
void ContactCorrectionStrategy::Helper::fixContactFromVia(su_home_t* home, sip_t* msg, const sip_via_t* via) {
	sip_contact_t* ctt = msg->sip_contact;
	const char* received = via->v_received;
	const char* rport = via->v_rport;
	const char* via_transport = sip_via_transport(via);
	bool is_frontend = (via->v_next == NULL); // True if we are the first proxy the request is going through.
	bool single_contact = (ctt != NULL && ctt->m_next == NULL);

	// Nothing to do.
	if (NatTraversalStrategy::Helper::empty(received) && NatTraversalStrategy::Helper::empty(rport)) return;

	// Case where the "rport" is not empty  but received is empty (because the host was correct).
	if (NatTraversalStrategy::Helper::empty(received)) received = via->v_host;

	// If no "rport" was given, then trust the via port.
	if (rport == NULL) rport = via->v_port;

	for (; ctt != NULL; ctt = ctt->m_next) {
		if (ctt->m_url->url_host) {
			const char* host = ctt->m_url->url_host;
			char ct_transport[20] = {0};
			if (url_has_param(ctt->m_url, "gr")) {
				SLOGD << "Gruu found in contact header [" << ctt << "] for message [" << msg
				      << "] skipping nat fixing process for contact";
				continue;
			}
			url_param(ctt->m_url->url_params, "transport", ct_transport, sizeof(ct_transport) - 1);
			// If we have a single contact, and we are the front-end proxy, or if we found an ip:port in a contact
			// that seems incorrect because the same appeared fixed in the via, then fix it.
			if ((is_frontend && single_contact) || (ModuleToolbox::urlHostMatch(host, via->v_host) &&
			                                        ModuleToolbox::sipPortEquals(ctt->m_url->url_port, via->v_port) &&
			                                        ModuleToolbox::transportEquals(via_transport, ct_transport))) {

				if (!ModuleToolbox::urlHostMatch(host, received) ||
				    !ModuleToolbox::sipPortEquals(ctt->m_url->url_port, rport)) {
					LOGD("Fixing contact header with %s:%s to %s:%s", ctt->m_url->url_host,
					     ctt->m_url->url_port ? ctt->m_url->url_port : "", received, rport ? rport : "");
					ModuleToolbox::urlSetHost(home, ctt->m_url, received);
					ctt->m_url->url_port = rport;
				}
				NatTraversalStrategy::Helper::fixTransport(home, ctt->m_url, via_transport);
			}
		}
	}
}

/*
 * Check whether the "Contact" header field needs to be fixed.
 */
bool ContactCorrectionStrategy::Helper::contactNeedsToBeFixed(const tport_t* internalTport,
                                                              const std::shared_ptr<SipEvent>& ev) const {
	const shared_ptr<MsgSip>& ms = ev->getMsgSip();
	sip_contact_t* ct = ms->getSip()->sip_contact;
	tport_t* primary = tport_parent(ev->getIncomingTport().get());
	return ct && !url_has_param(ct->m_url, mContactCorrectionParameter.c_str()) && !url_has_param(ct->m_url, "gr") &&
	       !msg_params_find(ct->m_params, "isfocus") && internalTport != primary;
}

const std::string& ContactCorrectionStrategy::Helper::getContactCorrectionParameter() const {
	return mContactCorrectionParameter;
}

ContactCorrectionStrategy::ContactCorrectionStrategy(Agent* agent, const std::string& contactCorrectionParameter)
    : NatTraversalStrategy(agent), mHelper(contactCorrectionParameter) {
}

void ContactCorrectionStrategy::preProcessOnRequestNatHelper(const std::shared_ptr<RequestSipEvent>& ev) const {
	const auto& ms = ev->getMsgSip();
	auto* sip = ms->getSip();

	// If we receive a request whose first via is wrong (received or rport parameters are present),
	// fix any possible Contact headers with the same wrong ip address and ports.
	if (mHelper.contactNeedsToBeFixed(mAgent->getInternalTport(), ev)) {
		Helper::fixContactFromVia(ms->getHome(), sip, sip->sip_via);
	}
}

void ContactCorrectionStrategy::addRecordRouteNatHelper(const std::shared_ptr<RequestSipEvent>& ev) const {
	ModuleToolbox::addRecordRouteIncoming(mAgent, ev);
}

/*
 * TODO: Fixing contacts in responses is unreliable: we can't know if we are the first hop of the response.
 * This feature should be removed from Flexisip.
 */
void ContactCorrectionStrategy::onResponseNatHelper(const std::shared_ptr<ResponseSipEvent>& ev) const {
	const auto& ms = ev->getMsgSip();
	auto* sip = ms->getSip();
	auto* home = ev->getHome();
	const auto* st = sip->sip_status;
	const auto* cseq = sip->sip_cseq;

	// In responses that establish a dialog, masquerade Contact so that further requests (including the ACK) are routed
	// in the same way
	if (cseq && (cseq->cs_method == sip_method_invite || cseq->cs_method == sip_method_subscribe)) {
		if (st->st_status >= 200 && st->st_status <= 299) {
			const auto ct = sip->sip_contact;
			if (ct) {
				if (mHelper.contactNeedsToBeFixed(mAgent->getInternalTport(), ev)) {
					Helper::fixContactInResponse(home, ms->getMsg(), sip);
				}

				if (sip->sip_via && sip->sip_via->v_next && !sip->sip_via->v_next->v_next /* is last hop */) {
					if (url_has_param(ct->m_url, mHelper.getContactCorrectionParameter().c_str()) /* is verified */) {
						// Via contains client and first proxy
						LOGD("Removing \"verified\" parameter from response contact");
						ct->m_url->url_params = url_strip_param_string(su_strdup(home, ct->m_url->url_params),
						                                               mHelper.getContactCorrectionParameter().c_str());
					}
					return;
				}

				// The "verified" parameter must be added whenever we fix or not the Contact, in order to signal other
				// nodes processing this response that the contact has been processed already.
				if (!url_has_param(ct->m_url, mHelper.getContactCorrectionParameter().c_str())) {
					url_param_add(home, ct->m_url, mHelper.getContactCorrectionParameter().c_str());
				}
			}
		}
	}
}

url_t* ContactCorrectionStrategy::getTportDestFromLastRoute(const std::shared_ptr<RequestSipEvent>&,
                                                            const sip_route_t*) const {
	return nullptr;
}

void ContactCorrectionStrategy::addRecordRouteForwardModule(const std::shared_ptr<RequestSipEvent>& ev,
                                                            tport_t* tport,
                                                            url_t*) const {
	ModuleToolbox::addRecordRoute(mAgent, ev, (tport == (tport_t*)-1) ? nullptr : tport);
}

void ContactCorrectionStrategy::addPathOnRegister(const std::shared_ptr<RequestSipEvent>& ev,
                                                  tport_t* tport,
                                                  const char* uniq) const {
	ModuleToolbox::addPathHeader(mAgent, ev, (tport == (tport_t*)-1) ? nullptr : tport, uniq);
}

} // namespace flexisip