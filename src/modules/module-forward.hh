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

	/**
	 * Send the request to the desired destination url.
	 *
	 * @param dest url of the request
	 */
	void sendRequest(const std::unique_ptr<RequestSipEvent>& ev, url_t* dest,  const std::optional<SipUri>& lastRoute = std::nullopt);

private:
	bool isAClusterNode(const url_t* url) const;

	static ModuleInfo<ForwardModule> sInfo;

	su_home_t mHome{};
	ConditionalRouteMap mRoutesMap{};
	std::string mDefaultTransport{};
	std::list<std::string> mParamsToRemove{};
	std::list<std::string> mClusterNodes{};
	bool mRewriteReqUri{};
	bool mAddPath{};
};

} // namespace flexisip