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

#include <string>

#include "generic-http-client.hh"
#include "pushnotification/legacy/legacy-client.hh"

namespace flexisip {
namespace pushnotification {

/**
 * PNR (Push Notification Request) client designed to send push notification toa custom push API.
 */
class GenericHttpClient : public LegacyClient {

public:
	static std::unique_ptr<GenericHttpClient> makeUnique(const sofiasip::Url& url,
	                                                     Method method,
	                                                     const std::string& name,
	                                                     unsigned maxQueueSize,
	                                                     const Service* service);

	GenericHttpClient(std::unique_ptr<Transport>&& transport,
	                  const std::string& name,
	                  unsigned maxQueueSize,
	                  const Service* service);

	std::shared_ptr<Request> makeRequest(PushType,
	                                     const std::shared_ptr<const PushInfo>&,
	                                     const std::map<std::string, std::shared_ptr<Client>>&) override;
};
} // namespace pushnotification
} // namespace flexisip
