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

#pragma once

#include <memory>

#include "agent.hh"
#include "sofia-sip/tport.h"
#include "utils/flow.hh"

namespace flexisip {
/**
 * Set of useful functions used across several modules.
 */
namespace module_toolbox {

msg_auth_t* findAuthorizationForRealm(su_home_t* home, msg_auth_t* au, const char* realm);

void addRecordRouteIncoming(Agent* agent, RequestSipEvent& ev, const Flow::Token& token = "");
bool addRecordRoute(Agent* agent, MsgSip& msg, const tport_t* tport, const Flow::Token& token = "");

void cleanAndPrependRoute(Agent* agent, msg_t* msg, sip_t* sip, sip_route_t* route);

bool sipPortEquals(const char* p1, const char* p2, const char* transport = nullptr);
int sipPortToInt(const char* port);

bool fromMatch(const sip_from_t* from1, const sip_from_t* from2);
bool matchesOneOf(const std::string& item, const std::list<std::string>& set);

bool fixAuthChallengeForSDP(su_home_t* home, msg_t* msg, sip_t* sip);
bool transportEquals(const char* tr1, const char* tr2);
bool isNumeric(const char* host);
bool isManagedDomain(const Agent* agent, const std::list<std::string>& domains, const url_t* url);
void addRoutingParam(su_home_t* home, sip_contact_t* contacts, const std::string& routingParam, const char* domain);
sip_route_s* prependNewRoutable(msg_t* msg, sip_t* sip, sip_route_t*& sipr, sip_route_t* value);
void addPathHeader(
    Agent* agent, MsgSip& msg, const tport_t* tport, const char* uniq = nullptr, const Flow::Token& token = "");

/**
 * @note takes into account that each argument could be an ipv6 address enclosed in brackets
 */
bool urlHostMatch(const char* host1, const char* host2);
/**
 * @note takes into account that each argument could be an ipv6 address enclosed in brackets
 */
bool urlHostMatch(const url_t* url, const char* host);
/**
 * @note takes into account that each argument could be an ipv6 address enclosed in brackets
 */
bool urlHostMatch(const std::string& host1, const std::string& host2);

/**
 * @note takes into account that if it is an ipv6 address, then brackets are removed
 */
std::string getHost(const char* host);

std::string urlGetHost(url_t* url);
void urlSetHost(su_home_t* home, url_t* url, const char* host);
bool urlIsResolved(url_t* uri);

/**
 * @return true if via and url represent the same network address
 */
bool urlViaMatch(const url_t* url, const sip_via_t* via, bool use_received_rport);

/**
 * @return true if the destination represented by url is present in the via chain
 */
bool viaContainsUrl(const sip_via_t* vias, const url_t* url);

/**
 * @return true if the destination host contained in 'url' is present in via headers (helps for loop detection)
 */
bool viaContainsUrlHost(const sip_via_t* vias, const url_t* url);

/**
 * @return the next hop by skipping possible Route headers pointing to this proxy
 */
const url_t* getNextHop(Agent* ag, const sip_t* sip, bool* isRoute);

/**
 * @return true if the two url represent the same transport channel (IP, port and protocol)
 */
bool urlTransportMatch(const url_t* url1, const url_t* url2);
std::string urlGetTransport(const url_t* url);
void removeParamsFromContacts(su_home_t* home, sip_contact_t* c, std::list<std::string>& params);
void removeParamsFromUrl(su_home_t* home, url_t* u, std::list<std::string>& params);
sip_unknown_t* getCustomHeaderByName(const sip_t* sip, const char* name);
int getCpuCount();
sip_via_t* getLastVia(sip_t* sip);
/**
 * @note same as url_make() from sofia, but unsure that the url is sip or sips; otherwise return NULL
 */
url_t* sipUrlMake(su_home_t* home, const char* value);

/**
 * @note this function is compliant with RFC1918
 */
bool isPrivateAddress(const char* host);

} // namespace module_toolbox

// NOLINTNEXTLINE(misc-unused-alias-decls) Deprecated alias to transition existing code smoothly.
namespace ModuleToolbox = module_toolbox;

} // namespace flexisip