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

#include "body-utils.hh"
#include "generic-enums.hh"
#include "pushnotification/request.hh"
#include "pushnotification/service.hh"
#include "utils/transport/http/http-message.hh"

namespace flexisip::pushnotification {

class GenericHttp2Request : public Request, public HttpMessage {
public:
	/**
	 * Create a HTTP Request with path and url parameters customized based on the push information
	 */
	GenericHttp2Request(PushType pType,
	                    const std::shared_ptr<const PushInfo>& pInfo,
	                    Method method,
	                    const std::string& host,
	                    const std::string& port,
	                    std::string path,         // copy needed
	                    std::string urlParameters // copy needed
	);

	/**
	 * Create a HTTP POST Request with a JSON body generated from the push information
	 */
	GenericHttp2Request(PushType pType,
	                    const std::shared_ptr<const PushInfo>& pInfo,
	                    const std::string& host,
	                    const std::string& port,
	                    const std::string& path,
	                    const std::string& apiKey,
	                    const JsonBodyGenerationFunc& bodyGenerationFunc);

	std::string getAppIdentifier() const noexcept override {
		return Service::kExternalClientName;
	}
};

} // namespace flexisip::pushnotification