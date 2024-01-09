/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>
#include <string>
#include <variant>

#include "flexisip/configmanager.hh"

#include "libhiredis-wrapper/redis-auth.hh"

namespace flexisip::redis::async {

struct RedisParameters {
	static RedisParameters redisParamsFromRegistarConf(const GenericStruct* registarConf) {
		RedisParameters params;
		params.domain = registarConf->get<ConfigString>("redis-server-domain")->read();
		params.port = registarConf->get<ConfigInt>("redis-server-port")->read();
		params.useSlavesAsBackup = registarConf->get<ConfigBoolean>("redis-use-slaves-as-backup")->read();
		params.auth = [&registarConf]() -> decltype(auth) {
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
		}();
		params.mSlaveCheckTimeout = std::chrono::duration_cast<std::chrono::seconds>(
		    registarConf->get<ConfigDuration<std::chrono::seconds>>("redis-slave-check-period")->read());

		return params;
	}

	std::string domain{};
	std::variant<redis::auth::None, redis::auth::Legacy, redis::auth::ACL> auth{};
	int port = 0;
	std::chrono::seconds mSlaveCheckTimeout{0};
	bool useSlavesAsBackup = true;
};

} // namespace flexisip::redis::async
