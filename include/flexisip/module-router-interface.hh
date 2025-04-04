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

namespace flexisip {

class ForkContext;
class RequestSipEvent;

/**
 * Interface for the ModuleRouter object, this interface is under construction.
 * For now it allow to mock the Agent in some test cases.
 */
class ModuleRouterInterface {
public:
	virtual ~ModuleRouterInterface() = default;

	virtual void sendToInjector(std::unique_ptr<RequestSipEvent>&& ev,
	                            const std::shared_ptr<ForkContext>& context,
	                            const std::string& contactId) = 0;
};

} // namespace flexisip
