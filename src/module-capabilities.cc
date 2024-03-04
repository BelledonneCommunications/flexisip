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

#include "module-capabilities.hh"

#include "agent.hh"
#include "eventlogs/writers/event-log-writer.hh"

namespace flexisip {

void ModuleCapabilities::onRequest(std::shared_ptr<RequestSipEvent>& ev) {
	// Test that the request is an OPTIONS
	const auto& msg = ev->getMsgSip();
	if (msg && msg->getSip()->sip_request->rq_method == sip_method_options) {
		// Test that the request is for this proxy i.e.:
		//   1. there is no Route header;
		//   2. the Request-URI as no user part;
		//   3. the domain and port of the Request-URI match this proxy.
		const auto* requestURI = msg->getSip()->sip_request->rq_url;
		if (msg->getSip()->sip_route == nullptr && requestURI->url_user == nullptr && mAgent->isUs(requestURI, true)) {
			SLOGI << "Replying to OPTIONS request";
			ev->reply(SIP_200_OK, TAG_END());
		}
	}
}

const ModuleInfo<ModuleCapabilities> ModuleCapabilities::sInfo{
    "Capabilities",
    "Enable this module in order the proxy replies to OPTION requests by “200 Ok”. Today, no "
    "supported header is added in the response, so this mechanism cannot be used for capabilities introspection.\n"
    "If the module is disabled, the request will be silently discarded.",
    {"GarbageIn"},
    ModuleInfoBase::ModuleOid::Capabilities,
    [](GenericStruct&) {}};

} // namespace flexisip
