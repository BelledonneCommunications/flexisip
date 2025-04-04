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

#include <sofia-sip/msg_header.h>
#include <sofia-sip/nta_tport.h>
#include <sofia-sip/tport.h>

#include "agent.hh"
#include "utils/flow.hh"

namespace flexisip {

/*
 * Some useful routines.
 */
class ModuleToolbox {
public:
	static msg_auth_t* findAuthorizationForRealm(su_home_t* home, msg_auth_t* au, const char* realm);

	static void addRecordRouteIncoming(Agent* agent, RequestSipEvent& ev, const Flow::Token& token = "");
	static void addRecordRoute(Agent* agent, RequestSipEvent& ev, const tport_t* tport, const Flow::Token& token = "");

	static void cleanAndPrependRoute(Agent* agent, msg_t* msg, sip_t* sip, sip_route_t* route);

	static bool sipPortEquals(const char* p1, const char* p2, const char* transport = nullptr);
	static int sipPortToInt(const char* port);

	static bool fromMatch(const sip_from_t* from1, const sip_from_t* from2);
	static bool matchesOneOf(const std::string& item, const std::list<std::string>& set);

	static bool fixAuthChallengeForSDP(su_home_t* home, msg_t* msg, sip_t* sip);
	static bool transportEquals(const char* tr1, const char* tr2);
	static bool isNumeric(const char* host);
	static bool isManagedDomain(const Agent* agent, const std::list<std::string>& domains, const url_t* url);
	static void
	addRoutingParam(su_home_t* home, sip_contact_t* contacts, const std::string& routingParam, const char* domain);
	static struct sip_route_s* prependNewRoutable(msg_t* msg, sip_t* sip, sip_route_t*& sipr, sip_route_t* value);
	static void
	addPathHeader(Agent* agent, MsgSip& ms, tport_t* tport, const char* uniq = nullptr, const Flow::Token& token = "");

	// These methods do host comparison taking into account that each one of argument can be an ipv6 address enclosed in
	// brakets.
	static bool urlHostMatch(const char* host1, const char* host2);
	static bool urlHostMatch(const url_t* url, const char* host);
	static bool urlHostMatch(const std::string& host1, const std::string& host2);

	// Returns the host taking into account that if it is an ipv6 address, then brakets are removed.
	static std::string getHost(const char* host);

	static std::string urlGetHost(url_t* url);
	static void urlSetHost(su_home_t* home, url_t* url, const char* host);
	static bool urlIsResolved(url_t* uri);

	// Returns true if via and url represent the same network address.
	static bool urlViaMatch(const url_t* url, const sip_via_t* via, bool use_received_rport);

	// Returns true if the destination represented by url is present in the via chain.
	static bool viaContainsUrl(const sip_via_t* vias, const url_t* url);
	// Returns true if the destination host contained in 'url' is present in via headers. This helps loop detection.
	static bool viaContainsUrlHost(const sip_via_t* vias, const url_t* url);

	/* Return the next hop by skipping possible Route headers pointing to this proxy.*/
	static const url_t* getNextHop(Agent* ag, const sip_t* sip, bool* isRoute);

	// Returns true if the two url represent the same transport channel (IP, port and protocol).
	static bool urlTransportMatch(const url_t* url1, const url_t* url2);
	static std::string urlGetTransport(const url_t* url);
	static void removeParamsFromContacts(su_home_t* home, sip_contact_t* c, std::list<std::string>& params);
	static void removeParamsFromUrl(su_home_t* home, url_t* u, std::list<std::string>& params);
	static sip_unknown_t* getCustomHeaderByName(const sip_t* sip, const char* name);
	static int getCpuCount();
	static sip_via_t* getLastVia(sip_t* sip);
	/* same as url_make() from sofia, but unsure that the url is sip or sips; otherwise return NULL*/
	static url_t* sipUrlMake(su_home_t* home, const char* value);

private:
	static constexpr std::string_view mLogPrefix{"ModuleToolbox"};
};

} // namespace flexisip