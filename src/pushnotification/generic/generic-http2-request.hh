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

#include "generic-enums.hh"
#include "pushnotification/request.hh"
#include "pushnotification/service.hh"
#include "utils/transport/http/http-message.hh"

namespace flexisip::pushnotification {

class GenericHttp2Request : public Request, public HttpMessage {
public:
	GenericHttp2Request(flexisip::pushnotification::PushType pType,
	                    const std::shared_ptr<const PushInfo>& pInfo,
	                    Method method,
	                    const std::string& host,
	                    const std::string& port,
	                    const std::string& authKey,
	                    std::string path,         // copy needed
	                    std::string urlParameters // copy needed
	);

	std::string getAppIdentifier() const noexcept override {
		return Service::sGenericClientName;
	};
};

} // namespace flexisip::pushnotification
