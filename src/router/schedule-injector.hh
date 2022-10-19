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

#include <map>
#include <vector>

#include "inject-context.hh"
#include "injector.hh"

namespace flexisip {

/**
 * An injector that sort message by priority and then keep them in order.
 *
 * Every calls to Module::injectRequestEvent(RequestSipEvent ev) will be done in same order than calls to
 * ScheduleInjector::addContext(shared_ptr<ForkContext>& fork, string& contactId), matching between RequestSipEvent and
 * ForkContext.
 *
 * The previous statement is true for request of the same priority, every request with the header "Priority: non-urgent"
 * will be delayed as long as higher priority request remains. ScheduleInjector uses ForkContext::getPriority() to
 * determine InjectContext priority.
 */
class ScheduleInjector : public Injector {
	using InjectListType = std::list<InjectContext>;
	using InjectContextMap = std::map<std::string, InjectListType>;

public:
	explicit ScheduleInjector(Module* module) : Injector(module){};

	/**
	 * Try to inject the request if it is the first in the order created by ScheduleInjector::addContext and then :
	 *     - if the request is injected (first in the order) inject all the following request that were waiting, in
	 * order.
	 *     - if it is not injected, mark the injected context as ready to be injected (storing the RequestSipEvent).
	 */
	void injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev,
	                        const std::shared_ptr<ForkContext>& fork,
	                        const std::string& contactId) override;

	/**
	 * Create the order that will be enforced by ScheduleInjector::injectRequestEvent.
	 */
	void addContext(const std::shared_ptr<ForkContext>& fork, const std::string& contactId) override;

	/**
	 * Starting from the end of the list remove a context that don't need inject.
	 */
	void removeContext(const std::shared_ptr<ForkContext>& fork, const std::string& contactId) override;

private:
	void startInject(sofiasip::MsgSipPriority currentWorkingPriority,
	                 InjectListType& contactInjectContexts,
	                 const std::string& contactId);
	void continueInjectIfNeeded(sofiasip::MsgSipPriority currentWorkingPriority, const std::string& contactId);

	InjectContextMap& getMapFromPriority(sofiasip::MsgSipPriority msgSipPriority);
	bool areAllHigherPriorityMapEmpty(sofiasip::MsgSipPriority msgSipPriority, const std::string& contactId) const;

	InjectContextMap mEmergencyInjectContexts{};
	InjectContextMap mUrgentInjectContexts{};
	InjectContextMap mNormalInjectContexts{};
	InjectContextMap mNonUrgentInjectContexts{};
};

} // namespace flexisip
