/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "module-toolbox.hh"

#include <memory>

#include "agent.hh"
#include "domain-registrations.hh"
#include "sofia-sip/auth_digest.h"
#include "sofia-sip/msg_header.h"
#include "sofia-sip/tport.h"
#include "utils/flow.hh"

using namespace std;

namespace flexisip::module_toolbox {

static constexpr auto* kPrefix{"ModuleToolbox"};

msg_auth_t* findAuthorizationForRealm(su_home_t* home, msg_auth_t* au, const char* realm) {
	while (au) {
		auth_response_t r;
		memset(&r, 0, sizeof(r));
		r.ar_size = sizeof(r);
		auth_digest_response_get(home, &r, au->au_params);
		LOGD_CTX(kPrefix) << "Examining auth digest response " << r.ar_username << " " << r.ar_realm;
		if (strcasecmp(r.ar_realm, realm) == 0) {
			LOGD_CTX(kPrefix) << "Expected realm found: " << r.ar_realm;
			return au;
		}
		au = au->au_next;
	}
	LOGI_CTX(kPrefix) << "Authorization with expected realm '" << realm << "' not found" << realm;
	return nullptr;
}

bool sipPortEquals(const char* p1, const char* p2, const char* transport) {
	int n1, n2;
	if (transport == NULL || strcasecmp(transport, "TLS") == 0) n1 = n2 = 5060;
	else n1 = n2 = 5061;

	if (p1 && p1[0] != '\0') n1 = atoi(p1);
	if (p2 && p2[0] != '\0') n2 = atoi(p2);
	return n1 == n2;
}

int sipPortToInt(const char* port) {
	if (port == NULL || port[0] == '\0') return 5060;
	else return atoi(port);
}

void cleanAndPrependRoute(Agent* ag, msg_t* msg, sip_t* sip, sip_route_t* r) {
	// removes top route headers if they matches us
	while (sip->sip_route != NULL && ag->isUs(sip->sip_route->r_url)) {
		sip_route_remove(msg, sip);
	}

	if (r) prependNewRoutable(msg, sip, sip->sip_route, r);
}

void addRecordRoute(Agent* ag, RequestSipEvent& ev, const tport_t* tport, const Flow::Token& token) {
	msg_t* msg = ev.getMsgSip()->getMsg();
	sip_t* sip = ev.getMsgSip()->getSip();
	su_home_t* home = ev.getMsgSip()->getHome();
	url_t* url = NULL;

	if (tport) {
		DomainRegistrationManager* drm = ag->getDRM();
		if (drm) { // this finds public contact information for request received via domain registration connections.
			const url_t* reg_uri = drm->getPublicUri(tport);
			if (reg_uri) {
				url = url_hdup(home, reg_uri);
				LOGD_CTX(kPrefix) << "Public uri found from domain registration manager";
			}
		}
		if (!url) {
			tport = tport_parent(tport); // get primary transport, to get the public (server socket) ip/port
			const tp_name_t* name = tport_name(tport); // primary transport name

			url = ag->urlFromTportName(home, name);
			if (!url) {
				LOGE_CTX(kPrefix) << "urlFromTportName() returned NULL";
				return;
			}
		}
	} else {
		// default to Agent's default address.
		url = url_hdup(home, ag->getNodeUri());
	}

	url_param_add(home, url, "lr");
	if (ag->shouldUseRfc2543RecordRoute()) {
		if (url->url_type == url_sips) {
			url->url_type = url_sip;
			url->url_scheme = "sip";
			url_param_add(home, url, "transport=tls");
		}
	}

	if (!token.empty()) {
		if (url->url_user == nullptr) {
			url->url_user = su_strdup(home, token.data());
		} else {
			LOGD_CTX(kPrefix) << "Failed to add flow-token in sip uri, url_user is not empty";
		}
	}

	sip_record_route_t* rr = sip_record_route_create(home, url, NULL);
	if (!rr) {
		LOGE_CTX(kPrefix) << "sip_record_route_create() returned NULL";
		return;
	}

	if (!prependNewRoutable(msg, sip, sip->sip_record_route, rr)) {
		LOGD_CTX(kPrefix) << "Skipping addition of record route identical to top one";
		return;
	}

	LOGD_CTX(kPrefix) << "Record route added";
	ev.mRecordRouteAdded = true;
}

void addRecordRouteIncoming(Agent* ag, RequestSipEvent& ev, const Flow::Token& token) {
	if (ev.mRecordRouteAdded) return;

	const auto tport = ev.getIncomingTport();
	if (!tport) {
		LOGE_CTX(kPrefix) << "Cannot find incoming tport, cannot add a Record-Route";
		return;
	} else {
		// We have a tport, check if we are in a case of proxy to proxy communication.
		if (ev.getMsgSip()->getSip()->sip_record_route != NULL) { // There is already a record route.
			ag->applyProxyToProxyTransportSettings(tport.get());
		}
	}

	addRecordRoute(ag, ev, tport.get(), token);
}

bool fromMatch(const sip_from_t* from1, const sip_from_t* from2) {
	if (url_cmp(from1->a_url, from2->a_url) == 0) {
		if (from1->a_tag && from2->a_tag && strcmp(from1->a_tag, from2->a_tag) == 0) return true;
		if (from1->a_tag == NULL && from2->a_tag == NULL) return true;
	}
	return false;
}

bool matchesOneOf(const string& item, const list<string>& set) {
	list<string>::const_iterator it;
	for (it = set.begin(); it != set.end(); ++it) {
		const string& value = (*it);
		const char* tmp = value.c_str();
		if (tmp[0] == '*') {
			/*the wildcard matches everything*/
			return true;
		} else {
			size_t wildcardPosition = value.find("*");
			// if domain has a wildcard in it, try to match
			if (wildcardPosition != string::npos) {
				size_t beforeWildcard = item.find(value.substr(0, wildcardPosition));
				size_t afterWildcard = item.find(value.substr(wildcardPosition + 1));
				if (beforeWildcard != string::npos && afterWildcard != string::npos) {
					return true;
				}
			}
			if (strcmp(item.c_str(), tmp) == 0) return true;
		}
	}
	return false;
}

bool fixAuthChallengeForSDP(su_home_t* home, [[maybe_unused]] msg_t* msg, sip_t* sip) {
	sip_auth_t* auth;
	msg_param_t* par;
	auth = sip->sip_www_authenticate;
	if (auth == NULL) auth = sip->sip_proxy_authenticate;
	if (auth == NULL) return true;
	if (auth->au_params == NULL) return true;
	par = msg_params_find_slot((msg_param_t*)auth->au_params, "qop");
	if (par != NULL) {
		if (strstr(*par, "auth-int")) {
			LOGD_CTX(kPrefix) << "Authentication header has qop with 'auth-int', replacing by 'auth'";
			// if the qop contains "auth-int", replace it by "auth" so that it allows to modify the SDP
			*par = su_strdup(home, "qop=\"auth\"");
		}
	}
	return true;
}

void urlSetHost(su_home_t* home, url_t* url, const char* host) {
	if (strchr(host, ':') && host[0] != '[') {
		url->url_host = su_sprintf(home, "[%s]", host);
	} else url->url_host = su_strdup(home, host);
}

bool urlIsResolved(url_t* uri) {
	return isNumeric(uri->url_host) || (uri->url_port && uri->url_port[0] != '\0');
}

string getHost(const char* host) {
	if (host[0] == '[') {
		return string(host, 1, strlen(host) - 2);
	}
	return string(host);
}

string urlGetHost(url_t* url) {
	return getHost(url->url_host);
}

bool urlHostMatch(const char* host1, const char* host2) {
	size_t len1, len2;
	int ipv6 = 0;
	len1 = strlen(host1);
	if (host1[0] == '[') {
		host1++;
		len1 -= 2;
		ipv6++;
	} else if (strchr(host1, ':')) ipv6++;
	len2 = strlen(host2);
	if (host2[0] == '[') {
		host2++;
		len2 -= 2;
		ipv6++;
	} else if (strchr(host2, ':')) ipv6++;
	if (ipv6 == 2) {
		/*since there exist multiple text representations of ipv6 addresses, it is necessary to switch to binary
		 * representation to make the comparision*/
		string ip1(host1, len1), ip2(host2, len2);
		struct sockaddr_in6 addr1 = {0}, addr2 = {0};
		if (inet_pton(AF_INET6, ip1.c_str(), &addr1) == 1 && inet_pton(AF_INET6, ip2.c_str(), &addr2) == 1) {
			return memcmp(&addr1, &addr2, sizeof(addr1)) == 0;
		} else {
			LOGD_CTX(kPrefix) << "Comparing invalid IPv6 addresses " << host1 << " | " << host2;
		}
	}
	return strncasecmp(host1, host2, MAX(len1, len2)) == 0;
}

bool urlHostMatch(const url_t* url, const char* host) {
	return urlHostMatch(url->url_host, host);
}

bool urlHostMatch(const std::string& host1, const std::string& host2) {
	return urlHostMatch(host1.c_str(), host2.c_str());
}

bool transportEquals(const char* tr1, const char* tr2) {
	if (tr1 == NULL || tr1[0] == 0) tr1 = "UDP";
	if (tr2 == NULL || tr2[0] == 0) tr2 = "UDP";
	return strcasecmp(tr1, tr2) == 0;
}

bool urlViaMatch(const url_t* url, const sip_via_t* via, bool use_received_rport) {
	const char* via_host = NULL;
	const char* via_port = NULL;
	const char* via_transport = sip_via_transport(via);
	const char* url_host = url->url_host;
	const char* url_pt = url_port(url); // this function never returns NULL
	char url_transport[8] = "UDP";

	char maddr[50];
	if (url_param(url->url_params, "maddr", maddr, sizeof(maddr))) {
		url_host = maddr;
	}

	if (use_received_rport) {
		via_host = via->v_received;
		via_port = via->v_rport;
	}
	if (via_host == NULL) {
		via_host = via->v_host;
	}
	if (via_port == NULL) {
		via_port = via->v_port;
	}
	if (via_port == NULL) {
		if (strcasecmp(via_transport, "TLS") == 0) via_port = "5051";
		else via_port = "5060";
	}
	url_param(url->url_params, "transport", url_transport, sizeof(url_transport));
	if (strcmp(url->url_scheme, "sips") == 0) strncpy(url_transport, "TLS", sizeof(url_transport));

	return urlHostMatch(via_host, url_host) && strcmp(via_port, url_pt) == 0;
}

bool viaContainsUrl(const sip_via_t* vias, const url_t* url) {
	const sip_via_t* via;
	for (via = vias; via != NULL; via = via->v_next) {
		if (urlViaMatch(url, via, true)) return true;
	}
	return false;
}

bool viaContainsUrlHost(const sip_via_t* vias, const url_t* url) {
	const sip_via_t* via;
	for (via = vias; via != NULL; via = via->v_next) {
		if (strcasecmp(via->v_host, url->url_host) == 0 && strcasecmp(via->v_port, url->url_port) == 0) return true;
	}
	return false;
}

static const char* get_transport_name_sip(const char* transport) {
	if (transport == NULL || transport[0] == '\0') return "UDP";
	else if (strcasecmp(transport, "udp") == 0) return "UDP";
	else if (strcasecmp(transport, "tcp") == 0) return "TCP";
	else if (strcasecmp(transport, "tls") == 0) return "TLS";
	return "INVALID";
}

static const char* get_transport_name_sips(const char* transport) {
	if (transport == NULL || transport[0] == '\0') return "TLS";
	else if (strcasecmp(transport, "udp") == 0) return "DTLS";
	else if (strcasecmp(transport, "tcp") == 0) return "TLS";
	else if (strcasecmp(transport, "tls") == 0) return "TLS"; /*should not happen but not so serious*/
	return "INVALID";
}

static const char* url_get_transport(const url_t* url) {
	char transport[8] = {0};
	const char* ret = "UDP";

	url_param(url->url_params, "transport", transport, sizeof(transport));
	switch (url->url_type) {
		case url_sip:
			ret = get_transport_name_sip(transport);
			break;
		case url_sips:
			ret = get_transport_name_sips(transport);
			break;
		default:
			LOGE_CTX(kPrefix) << "Invalid url type " << static_cast<int>(url->url_type);
			break;
	}
	return ret;
}

string urlGetTransport(const url_t* url) {
	return url_get_transport(url);
}

bool urlTransportMatch(const url_t* url1, const url_t* url2) {
	if (strcasecmp(url_get_transport(url1), url_get_transport(url2)) != 0) return false;
	if (!urlHostMatch(url1->url_host, url2->url_host)) return false;
	if (strcmp(url_port(url1), url_port(url2)) != 0) return false;

	return true;
}

bool isNumeric(const char* host) {
	if (host[0] == '[') return true; // ipv6
	struct in_addr addr;
	return !!inet_aton(host, &addr); // inet_aton returns non zero if ipv4 address is valid.
}

bool isManagedDomain(const Agent* agent, const list<string>& domains, const url_t* url) {
	bool check = matchesOneOf(url->url_host, domains);
	if (check) {
		// additional check: if the domain is an ip address that is not this proxy, then it is not considered as a
		// managed domain for the registrar.
		// we need this to distinguish requests that needs registrar routing from already routed requests.
		if (isNumeric(url->url_host) && !agent->isUs(url, true)) {
			check = false;
		}
	}
	return check;
}

void addRoutingParam(su_home_t* home, sip_contact_t* c, const string& routingParam, const char* domain) {
	ostringstream oss;
	oss << routingParam << "=" << domain;
	string routing_param(oss.str());
	while (c != NULL) {
		url_param_add(home, c->m_url, routing_param.c_str());
		c = c->m_next;
	}
}

sip_route_t* prependNewRoutable(msg_t* msg, sip_t* sip, sip_route_t*& sipr, sip_route_t* value) {
	if (sipr == NULL) {
		sipr = value;
		return value;
	}

	/*make sure we are not already in*/
	if (sipr && url_cmp_all(sipr->r_url, value->r_url) == 0) return NULL;

	value->r_next = sipr;
	msg_header_remove_all(msg, (msg_pub_t*)sip, (msg_header_t*)sipr);
	msg_header_insert(msg, (msg_pub_t*)sip, (msg_header_t*)value);
	sipr = value;
	return value;
}

void addPathHeader(Agent* ag, MsgSip& ms, tport_t* tport, const char* uniq, const Flow::Token& token) {
	su_home_t* home = ms.getHome();
	msg_t* msg = ms.getMsg();
	sip_t* sip = ms.getSip();
	url_t* url;
	bool proxyToProxy = false;

	if (tport) {
		// check for proxy to proxy communication
		if (sip->sip_path != NULL) { // there was already a path
			proxyToProxy = true;
		}
		tport_t* primary_tport = tport_parent(tport);      // get primary transport
		const tp_name_t* name = tport_name(primary_tport); // primary transport name

		url = ag->urlFromTportName(home, name);
		if (!url) {
			LOGE_CTX(kPrefix) << "urlFromTportName() returned NULL";
			return;
		}
	} else {
		// default to Agent's default address.
		url = url_hdup(home, ag->getDefaultUri());
	}
	if (uniq && (ag->getDefaultUri() != ag->getClusterUri())) {
		char* lParam = su_sprintf(home, "fs-proxy-id=%s", uniq);
		url_param_add(home, url, lParam);
	}
	url_param_add(home, url, "lr");
	sip_path_t* path = (sip_path_t*)su_alloc(home, sizeof(sip_path_t));
	sip_path_init(path);

	if (!token.empty()) {
		if (url->url_user == nullptr) {
			url->url_user = su_strdup(home, token.data());
			url_param_add(home, url, "ob");
		} else {
			LOGD_CTX(kPrefix) << "Failed to add flow-token in sip uri, url_user is not empty";
		}
	}

	path->r_url[0] = *url;

	if (!prependNewRoutable(msg, sip, sip->sip_path, path)) {
		LOGD_CTX(kPrefix) << "Identical path already existing: " << url_as_string(home, url);
	} else {
		LOGI_CTX(kPrefix) << "Path added to: " << url_as_string(home, url);
		if (tport && proxyToProxy) {
			ag->applyProxyToProxyTransportSettings(tport);
		}
	}
}

const url_t* getNextHop(Agent* ag, const sip_t* sip, bool* isRoute) {
	const sip_route_t* route = sip->sip_route;
	while (route) {
		if (!ag->isUs(route->r_url)) {
			if (isRoute) *isRoute = true;
			return route->r_url;
		}
		route = route->r_next;
	}
	if (isRoute) *isRoute = false;
	return sip->sip_request->rq_url;
}

void removeParamsFromContacts(su_home_t* home, sip_contact_t* c, list<string>& params) {
	while (c) {
		removeParamsFromUrl(home, c->m_url, params);
		c = c->m_next;
	}
}

void removeParamsFromUrl(su_home_t* home, url_t* u, list<string>& params) {
	for (auto it = params.begin(); it != params.end(); ++it) {
		const char* tag = it->c_str();
		if (!url_has_param(u, tag)) continue;
		char* paramcopy = su_strdup(home, u->url_params);
		u->url_params = url_strip_param_string(paramcopy, tag);
	}
}

sip_unknown_t* getCustomHeaderByName(const sip_t* sip, const char* name) {
	sip_unknown_t* it;
	for (it = sip->sip_unknown; it != NULL; it = it->un_next) {
		if (strcasecmp(it->un_name, name) == 0) {
			return it;
		}
	}
	return NULL;
}

int getCpuCount() {
	int count = 0;
	char line[256] = {0};

	FILE* f = fopen("/proc/cpuinfo", "r");
	if (f != NULL) {
		while (fgets(line, sizeof(line), f)) {
			if (strstr(line, "processor") == line) count++;
		}
		LOGI_CTX(kPrefix) << "Found " << count << " processors";
		fclose(f);
	} else {
		LOGE_CTX(kPrefix) << "Not implemented outside of Linux";
		count = 1;
	}
	return count;
}

sip_via_t* getLastVia(sip_t* sip) {
	sip_via_t* ret;
	ret = sip->sip_via;
	while (ret->v_next) {
		ret = ret->v_next;
	}
	return ret;
}

url_t* sipUrlMake(su_home_t* home, const char* value) {
	url_t* ret = url_make(home, value);
	if (ret) {
		if (ret->url_type != url_sip && ret->url_type != url_sips) {
			su_free(home, ret);
			ret = NULL;
		}
	}
	return ret;
}

bool isPrivateAddress(const char* host) {
	if (host == nullptr) return false;

	static const auto privateIpRegex =
	    regex{R"((^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.))"};
	return regex_search(host, privateIpRegex);
}

} // namespace flexisip::module_toolbox