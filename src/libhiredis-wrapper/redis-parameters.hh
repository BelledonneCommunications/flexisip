/** Copyright (C) 2010-2024 Belledonne Communications SARL
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
	std::string domain{};
	std::variant<redis::auth::None, redis::auth::Legacy, redis::auth::ACL> auth{};
	int port = 0;
	int timeout = 0;
	std::chrono::seconds mSlaveCheckTimeout{0};
	bool useSlavesAsBackup = true;

	static RedisParameters fromRegistrarConf(GenericStruct const*);
};

} // namespace flexisip::redis::async
