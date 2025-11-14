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
#include <optional>

#include "sofia-sip/su_alloc.h"
#include "sofia-sip/tport.h"
#include "sofia-sip/url.h"

#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/utils/sip-uri.hh"

namespace flexisip {

class Agent;
class RequestSipEvent;
class ResponseSipEvent;

using MsgSip = sofiasip::MsgSip;

/**
 * Strategies to correctly route requests to UACs that are routing their requests through NATs.
 */
class NatTraversalStrategy {
public:
	/**
	 * Utility methods for all strategies.
	 */
	class Helper {
	public:
		/**
		 * Check whether the pointer is empty or if pointed data is null terminator.
		 */
		static bool empty(const char* value);
		/**
		 * Fix the path url using "rport" and "received" from the first "VIA" header field.
		 */
		static void fixPath(const std::shared_ptr<MsgSip>& ms);
		/**
		 * Fix "transport" parameter value in provided url.
		 */
		static void fixTransport(su_home_t* home, url_t* url, const char* transport);
	};

	NatTraversalStrategy() = delete;
	explicit NatTraversalStrategy(Agent* agent);
	virtual ~NatTraversalStrategy() = default;

	/**
	 * Run a specific operation before running the code in NatHelper::onRequest().
	 */
	virtual void preProcessOnRequestNatHelper(const RequestSipEvent& ev) const = 0;

	/**
	 * Add a "Record-Route" header field when a request is processed by the NatHelper module.
	 */
	virtual void addRecordRouteNatHelper(RequestSipEvent& ev) const = 0;

	/**
	 * Code executed in NatHelper::onResponse().
	 */
	virtual void onResponseNatHelper(const ResponseSipEvent& ev) const = 0;

	/**
	 * Compute the destination url (request URI) from information contained in the last "Route" header field.
	 */
	virtual url_t* getTportDestFromLastRoute(const RequestSipEvent& ev, const sip_route_t* lastRoute) const = 0;

	/**
	 * Add a "Record-Route" header field to the request when it goes through the Forward module.
	 */
	virtual void addRecordRouteForwardModule(RequestSipEvent& ev, tport_t* tport, url_t* lastRouteUrl) const = 0;

	/**
	 * Add a "Path" header field to the REGISTER request.
	 */
	virtual void addPathOnRegister(RequestSipEvent& ev, tport_t* tport, const char* uniq) const = 0;

protected:
	Agent* mAgent;
};

} // namespace flexisip