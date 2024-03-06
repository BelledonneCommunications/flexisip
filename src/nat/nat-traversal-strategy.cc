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

#include "nat-traversal-strategy.hh"

#include <memory>

#include <sofia-sip/sip.h>
#include <sofia-sip/su_alloc.h>
#include <sofia-sip/url.h>

#include "flexisip/module.hh"

#include "module-toolbox.hh"

using namespace std;

namespace flexisip {

NatTraversalStrategy::NatTraversalStrategy(Agent* agent) : mAgent(agent) {
}

/*
 * Check whether the pointer is empty or if pointed data is null terminator.
 */
bool NatTraversalStrategy::Helper::empty(const char* value) {
	return value == NULL || value[0] == '\0';
}

/*
 * Fix path url using "rport" and "received" from the first "VIA" header field.
 */
void NatTraversalStrategy::Helper::fixPath(const std::shared_ptr<MsgSip>& ms) {
	sip_t* sip = ms->getSip();
	const sip_via_t* via = sip->sip_via;
	const char* received = via->v_received;
	const char* rport = via->v_rport;
	const char* transport = sip_via_transport(via);

	url_t* path = sip->sip_path->r_url;
	if (empty(received)) received = via->v_host;
	if (!rport) rport = via->v_port;
	if (!transport) transport = "udp";
	ModuleToolbox::urlSetHost(ms->getHome(), path, received);
	path->url_port = rport;
	fixTransport(ms->getHome(), path, transport);
}

/*
 * Fix "transport" parameter value in provided url.
 */
void NatTraversalStrategy::Helper::fixTransport(su_home_t* home, url_t* url, const char* transport) {
	if (url_has_param(url, "transport")) {
		url->url_params = url_strip_param_string(su_strdup(home, url->url_params), "transport");
	}
	if (url->url_type != url_sips) {
		const char* url_transport = NULL;
		if (strcasecmp(transport, "TCP") == 0) url_transport = "tcp";
		else if (strcasecmp(transport, "TLS") == 0) url_transport = "tls";
		if (url_transport) url_param_add(home, url, su_sprintf(home, "transport=%s", url_transport));
	}
}

} // namespace flexisip