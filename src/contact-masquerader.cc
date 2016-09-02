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

#include "contact-masquerader.hh"

using namespace std;

/*add a parameter like "CtRt15.128.128.2=tcp:201.45.118.16:50025" in the contact, so that we know where is the client
 when we later have to route an INVITE to him */
void ContactMasquerader::masquerade(su_home_t *home, sip_contact_t *c, const char *domain) {
	if (c == NULL || c->m_url->url_host == NULL) {
		LOGD("Sip contact or url is null");
		return;
	}

	url_t *ct_url = c->m_url;
	if (ct_url->url_scheme && ct_url->url_scheme[0] == '*') {
		SLOGD << "not masquerading star contact";
		return;
	}

	// grab the transport of the contact uri
	char ct_tport[32] = "udp";
	if (url_param(ct_url->url_params, "transport", ct_tport, sizeof(ct_tport)) > 0) {
	}

	// Create parameter
	string param = mCtRtParamName + "=" + ct_tport + ":";
	if (domain) {
		// param=tport:domain
		param += domain;
	} else {
		// param=tport:ip_prev_hop:port_prev_hop
		param += ct_url->url_host;
		param += ":";
		param += url_port(ct_url);
	}

	// Add parameter
	SLOGD << "Rewriting contact with param [" << param << "]";
	if (url_param_add(home, ct_url, param.c_str())) {
		LOGE("Cannot insert url param [%s]", param.c_str());
	}

	/*masquerade the contact, so that later requests (INVITEs) come to us */
	const url_t *preferredRoute = mAgent->getPreferredRouteUrl();
	ct_url->url_host = preferredRoute->url_host;
	ct_url->url_port = url_port(preferredRoute);
	ct_url->url_scheme = preferredRoute->url_scheme;
	ct_url->url_params = url_strip_param_string(su_strdup(home, ct_url->url_params), "transport");
	char tport_value[64];
	if (url_param(preferredRoute->url_params, "transport", tport_value, sizeof(tport_value)) > 0) {
		char *lParam = su_sprintf(home, "transport=%s", tport_value);
		url_param_add(home, ct_url, lParam);
	}
	SLOGD << "Contact has been rewritten to " << url_as_string(home, ct_url);
}

void ContactMasquerader::masquerade(std::shared_ptr<SipEvent> ev, bool insertDomain) {
		const char *domain = insertDomain ? ev->getSip()->sip_from->a_url->url_host : NULL;
		sip_contact_t *contact = ev->getSip()->sip_contact;
		while(contact) {
			if(contact->m_expires && strcmp(contact->m_expires, "0") == 0 && (contact != ev->getSip()->sip_contact || contact->m_next)) {
				LOGD("Removing one contact header: %s", url_as_string(ev->getHome(), contact->m_url));
				sip_contact_t *tmp = contact->m_next;
				msg_header_remove(ev->getMsgSip()->getMsg(), (msg_pub_t *)ev->getSip(), (msg_header_t *)contact);
				contact = tmp;
			} else {
				masquerade(ev->getHome(), contact, domain);
				contact = contact->m_next;
			}
		}
}

void ContactMasquerader::restore(su_home_t *home, url_t *dest, char ctrt_param[64], const char *new_param) {
	// first remove param
	dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), mCtRtParamName.c_str());

	// test and remove maddr param
	if (url_has_param(dest, "maddr")) {
		dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), "maddr");
	}

	// test and remove transport param
	if (url_has_param(dest, "transport")) {
		dest->url_params = url_strip_param_string(su_strdup(home, dest->url_params), "transport");
	}

	// second change dest to
	char *tend = strchr(ctrt_param, ':');
	if (!tend) {
		LOGD("Skipping url rewrite: first ':' not found");
		return;
	}

	const char *transport = su_strndup(home, ctrt_param, tend - ctrt_param);
	const url_t *paramurl = url_format(home, "sip:%s", tend + 1);

	if (!paramurl) {
		LOGE("ContactMasquerader::restore() aborted.");
		return;
	}
	dest->url_host = paramurl->url_host; // move ownership
	dest->url_port = paramurl->url_port; // move ownership
	if (strcasecmp(transport, "udp") != 0) {
		char *t_param = su_sprintf(home, "transport=%s", transport);
		url_param_add(home, dest, t_param);
	}

	if (new_param) {
		url_param_add(home, dest, new_param);
	}

	LOGD("Request url changed to %s", url_as_string(home, dest));
}
