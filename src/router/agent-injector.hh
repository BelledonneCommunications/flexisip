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

#include "injector.hh"

namespace flexisip {

/**
 * Really basic Injector implementation that simply call Module::injectRequestEvent on every
 * Module::injectRequestEvent call.
 */
class AgentInjector : public Injector {
public:
	AgentInjector(ModuleRouter* router) : Injector(router){};

	void injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev,
	                        [[maybe_unused]] const std::shared_ptr<ForkContext>& fork,
	                        [[maybe_unused]] const std::string& contactId) override {
		mModule->injectRequestEvent(ev);
	}
};

} // namespace flexisip
