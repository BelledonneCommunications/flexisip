/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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
#include <string>

#include "flexisip/event.hh"
#include "flexisip/fork-context/fork-context.hh"
#include "flexisip/module-router.hh"

namespace flexisip {

/**
 * Interface you need to implement to be used as an injector by ModuleRouter.
 *
 * Injectors must at least override Injector::injectRequestEvent.
 */
class Injector {
public:
	virtual ~Injector() = default;

	/**
	 * For evey call to Injector::injectRequestEvent(ev, fork, contactID) a call to Agent::injectRequestEvent(ev) MUST
	 * happen even if it can be delayed.
	 *
	 * @param ev The request to send.
	 * @param fork ForkContext associated to the request, can be optional.
	 * @param contactId unique id for the contact targeted by ev, can be optional.
	 */
	virtual void injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev,
	                                const std::shared_ptr<ForkContext>& fork,
	                                const std::string& contactId) = 0;

	virtual void addContext([[maybe_unused]] const std::shared_ptr<ForkContext>& fork, [[maybe_unused]] const std::string& contactId){};
	virtual void addContext([[maybe_unused]] const std::vector<std::shared_ptr<ForkContext>>& forks, [[maybe_unused]] const std::string& contactId){};

	virtual void removeContext([[maybe_unused]] const std::shared_ptr<ForkContext>& fork, [[maybe_unused]] const std::string& contactId){};

protected:
	explicit Injector(Module* aModule) : mModule(aModule){};

	Module* mModule;
};

} // namespace flexisip
