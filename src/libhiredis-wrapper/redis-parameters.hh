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

#include <chrono>
#include <string>
#include <variant>

#include "flexisip/configmanager.hh"

#include "libhiredis-wrapper/redis-auth.hh"

namespace flexisip::redis::async {

struct RedisParameters {
	std::string domain{};
	std::variant<redis::auth::None, redis::auth::Legacy, redis::auth::ACL> auth{};
	int port = 0;
	std::chrono::seconds mSlaveCheckTimeout{0};
	bool useSlavesAsBackup = true;
	std::chrono::seconds mSubSessionKeepAliveTimeout{0};

	static RedisParameters fromRegistrarConf(GenericStruct const*);
};

} // namespace flexisip::redis::async