/** Copyright (C) 2010-2024 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
