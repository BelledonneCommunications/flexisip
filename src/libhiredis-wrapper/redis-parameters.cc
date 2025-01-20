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

#include "redis-parameters.hh"

#include <exception>

namespace flexisip::redis::async {

RedisParameters RedisParameters::fromRegistrarConf(GenericStruct const* const registarConf) {
	return RedisParameters{
	    .domain = registarConf->get<ConfigString>("redis-server-domain")->read(),
	    .auth = [&registarConf]() -> decltype(auth) {
		    using namespace redis::auth;

		    const auto& password = registarConf->get<ConfigString>("redis-auth-password")->read();
		    if (password.empty()) {
			    return None();
		    }
		    const auto& user = registarConf->get<ConfigString>("redis-auth-user")->read();
		    if (user.empty()) {
			    return Legacy{password};
		    }
		    return ACL{user, password};
	    }(),
	    .port = registarConf->get<ConfigInt>("redis-server-port")->read(),
	    .mSlaveCheckTimeout = std::chrono::duration_cast<std::chrono::seconds>(
	        registarConf->get<ConfigDuration<std::chrono::seconds>>("redis-slave-check-period")->read()),
	    .useSlavesAsBackup = registarConf->get<ConfigBoolean>("redis-use-slaves-as-backup")->read(),
	    .mSubSessionKeepAliveTimeout =
	        [&registarConf] {
		        auto* param = registarConf->get<ConfigDuration<std::chrono::seconds>>(
		            "redis-subscription-keep-alive-check-period");
		        auto timeout = std::chrono::duration_cast<std::chrono::seconds>(param->read());
		        if (timeout.count() <= 0) throw std::runtime_error{param->getCompleteName() + " must be positive"};
		        return timeout;
	        }(),
	};
}

} // namespace flexisip::redis::async