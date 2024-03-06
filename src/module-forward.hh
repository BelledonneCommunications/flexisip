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

#include <list>
#include <memory>
#include <sstream>
#include <string>

#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_md5.h>
#include <sofia-sip/tport.h>

#include "flexisip/event.hh"
#include "flexisip/module-router.hh"
#include "flexisip/module.hh"

#include "agent.hh"
#include "conditional-routes.hh"
#include "domain-registrations.hh"
#include "etchosts.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "utils/uri-utils.hh"

namespace flexisip {

class ForwardModule : public Module, ModuleToolbox {
public:
	ForwardModule(Agent* ag);
	virtual ~ForwardModule();
	virtual void onDeclare(GenericStruct* module_config);
	virtual void onLoad(const GenericStruct* root);
	virtual void onRequest(std::shared_ptr<RequestSipEvent>& ev);
	virtual void onResponse(std::shared_ptr<ResponseSipEvent>& ev);
	void sendRequest(std::shared_ptr<RequestSipEvent>& ev, url_t* dest);

private:
	std::weak_ptr<ModuleRouter> mRouterModule;
	url_t* overrideDest(std::shared_ptr<RequestSipEvent>& ev, url_t* dest);
	url_t* getDestinationFromRoute(su_home_t* home, sip_t* sip);
	bool isLooping(std::shared_ptr<RequestSipEvent>& ev, const char* branch);
	unsigned int countVia(std::shared_ptr<RequestSipEvent>& ev);
	bool isAClusterNode(const url_t* url);
	su_home_t mHome;
	ConditionalRouteMap mRoutesMap;
	sip_route_t* mOutRoute;
	std::string mDefaultTransport;
	std::list<std::string> mParamsToRemove;
	std::list<std::string> mClusterNodes;
	bool mRewriteReqUri;
	bool mAddPath;
	static ModuleInfo<ForwardModule> sInfo;
};

} // namespace flexisip
