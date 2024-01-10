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

#pragma once

#include <memory>

#include <sofia-sip/su_alloc.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/url.h>

#include "flexisip/sofia-wrapper/msg-sip.hh"

namespace flexisip {

class Agent;
class RequestSipEvent;
class ResponseSipEvent;

using MsgSip = sofiasip::MsgSip;

/*
 * Strategies to correctly route requests to UACs that are routing their requests through NATs.
 */
class NatTraversalStrategy {
public:
	/*
	 * Utility methods for all strategies.
	 */
	class Helper {
	public:
		static bool empty(const char* value);
		static void fixPath(const std::shared_ptr<MsgSip>& ms);
		static void fixTransport(su_home_t* home, url_t* url, const char* transport);
	};

	NatTraversalStrategy() = delete;
	explicit NatTraversalStrategy(Agent* agent);
	virtual ~NatTraversalStrategy() = default;

	/*
	 * Run a specific operation before running the code in NatHelper::onRequest().
	 */
	virtual void preProcessOnRequestNatHelper(const std::shared_ptr<RequestSipEvent>& ev) const = 0;

	/*
	 * Add a record-route when a request is processed by NatHelper module.
	 */
	virtual void addRecordRouteNatHelper(const std::shared_ptr<RequestSipEvent>& ev) const = 0;

	/*
	 * Code executed in NatHelper::onResponse().
	 */
	virtual void onResponseNatHelper(const std::shared_ptr<ResponseSipEvent>& ev) const = 0;

	/*
	 * Get the destination url that will be used to determine the transport for the outgoing request.
	 */
	virtual url_t* getTportDestFromLastRoute(const std::shared_ptr<RequestSipEvent>& ev,
	                                         const sip_route_t* lastRoute) const = 0;

	/*
	 * Add a "record-route" to the request when it goes through the "Forward" module.
	 */
	virtual void addRecordRouteForwardModule(const std::shared_ptr<RequestSipEvent>& ev,
	                                         tport_t* tport,
	                                         url_t* lastRouteUrl) const = 0;

	/*
	 * Add "Path" header to the REGISTER request.
	 */
	virtual void
	addPathOnRegister(const std::shared_ptr<RequestSipEvent>& ev, tport_t* tport, const char* uniq) const = 0;

protected:
	Agent* mAgent;
};

} // namespace flexisip