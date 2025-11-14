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

#include <list>
#include <memory>
#include <string>

#include "agent.hh"
#include "conditional-routes.hh"
#include "domain-registrations.hh"
#include "flexisip/event.hh"
#include "flexisip/module-router.hh"
#include "flexisip/module.hh"
#include "utils/uri-utils.hh"

namespace flexisip {

class ForwardModule : public Module {
	friend std::shared_ptr<Module> ModuleInfo<ForwardModule>::create(Agent*);

public:
	ForwardModule(Agent* ag, const ModuleInfoBase* moduleInfo);
	~ForwardModule() override;

	void onLoad(const GenericStruct* mc) override;
	std::unique_ptr<RequestSipEvent> onRequest(std::unique_ptr<RequestSipEvent>&& ev) override;
	std::unique_ptr<ResponseSipEvent> onResponse(std::unique_ptr<ResponseSipEvent>&& response) override {
		onResponse(*response);
		return std::move(response);
	}
	void onResponse(ResponseSipEvent& ev);

	void sendRequest(std::unique_ptr<RequestSipEvent>& ev, url_t* dest, url_t* tportDest);

private:
	bool isAClusterNode(const url_t* url) const;
	url_t* overrideDest(MsgSip& ms, url_t* dest);
	/**
	 * @note It also sanitizes the destination url: "/etc/hosts" name resolution.
	 *
	 * @param dest destination url of the request, used by default to find the transport.
	 * @param tportDest alternative destination url used to find the transport. Will not be sanitized.
	 *
	 * @return the outgoing transport to use to send the request
	 */
	tport_t* findTransportToDestination(const RequestSipEvent& ev, url_t* dest, url_t* tportDest);

	static ModuleInfo<ForwardModule> sInfo;

	su_home_t mHome{};
	ConditionalRouteMap mRoutesMap{};
	sip_route_t* mOutRoute{};
	std::string mDefaultTransport{};
	std::list<std::string> mParamsToRemove{};
	std::list<std::string> mClusterNodes{};
	bool mRewriteReqUri{};
	bool mAddPath{};
};

} // namespace flexisip