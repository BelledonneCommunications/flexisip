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

#include "sofia-sip/nta.h"

#include "flexisip/sofia-wrapper/su-root.hh"

namespace flexisip {

class ResponseSipEvent;
class RequestSipEvent;
class OutgoingAgent;
class IncomingAgent;

/**
 * Interface for the Agent object, this interface is under construction.
 * For now it allow to mock the Agent in some test cases.
 */
class AgentInterface {
public:
	virtual ~AgentInterface() = default;

	virtual void injectRequestEvent(const std::shared_ptr<RequestSipEvent>& ev) = 0;
	virtual void injectResponseEvent(const std::shared_ptr<ResponseSipEvent>& ev) = 0;
	virtual void sendResponseEvent(const std::shared_ptr<ResponseSipEvent>& ev) = 0;

	virtual const std::shared_ptr<sofiasip::SuRoot>& getRoot() const noexcept = 0;

	virtual std::shared_ptr<OutgoingAgent> getOutgoingAgent() = 0;
	virtual std::shared_ptr<IncomingAgent> getIncomingAgent() = 0;
	virtual nta_agent_t* getSofiaAgent() const = 0;
};

} // namespace flexisip
